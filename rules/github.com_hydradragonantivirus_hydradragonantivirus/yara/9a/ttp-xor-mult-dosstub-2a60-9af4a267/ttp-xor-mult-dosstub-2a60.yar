rule TTP_XOR_MULT_DOSStub_2a60 {
  strings:
    $key_2a60 = { 7e 08 [2] 0a 10 [2] 4d 12 [2] 0a 03 [2] 44 0f [2] 48 05 [2] 5f 0e [2] 44 40 [2] 79 }

  condition:
    any of them
}