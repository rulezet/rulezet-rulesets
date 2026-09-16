rule TTP_XOR_MULT_DOSStub_2a76 {
  strings:
    $key_2a76 = { 7e 1e [2] 0a 06 [2] 4d 04 [2] 0a 15 [2] 44 19 [2] 48 13 [2] 5f 18 [2] 44 56 [2] 79 }

  condition:
    any of them
}