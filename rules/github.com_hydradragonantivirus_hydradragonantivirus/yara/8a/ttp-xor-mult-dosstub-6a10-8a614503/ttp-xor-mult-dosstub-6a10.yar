rule TTP_XOR_MULT_DOSStub_6a10 {
  strings:
    $key_6a10 = { 3e 78 [2] 4a 60 [2] 0d 62 [2] 4a 73 [2] 04 7f [2] 08 75 [2] 1f 7e [2] 04 30 [2] 39 }

  condition:
    any of them
}