rule TTP_XOR_MULT_DOSStub_1a10 {
  strings:
    $key_1a10 = { 4e 78 [2] 3a 60 [2] 7d 62 [2] 3a 73 [2] 74 7f [2] 78 75 [2] 6f 7e [2] 74 30 [2] 49 }

  condition:
    any of them
}