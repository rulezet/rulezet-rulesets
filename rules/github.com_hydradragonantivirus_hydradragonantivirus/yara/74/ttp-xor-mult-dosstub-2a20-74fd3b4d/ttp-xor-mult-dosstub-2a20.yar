rule TTP_XOR_MULT_DOSStub_2a20 {
  strings:
    $key_2a20 = { 7e 48 [2] 0a 50 [2] 4d 52 [2] 0a 43 [2] 44 4f [2] 48 45 [2] 5f 4e [2] 44 00 [2] 79 }

  condition:
    any of them
}