rule TTP_XOR_MULT_DOSStub_2a10 {
  strings:
    $key_2a10 = { 7e 78 [2] 0a 60 [2] 4d 62 [2] 0a 73 [2] 44 7f [2] 48 75 [2] 5f 7e [2] 44 30 [2] 79 }

  condition:
    any of them
}