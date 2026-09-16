rule TTP_XOR_MULT_DOSStub_2a26 {
  strings:
    $key_2a26 = { 7e 4e [2] 0a 56 [2] 4d 54 [2] 0a 45 [2] 44 49 [2] 48 43 [2] 5f 48 [2] 44 06 [2] 79 }

  condition:
    any of them
}