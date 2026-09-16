rule TTP_XOR_MULT_DOSStub_3815 {
  strings:
    $key_3815 = { 6c 7d [2] 18 65 [2] 5f 67 [2] 18 76 [2] 56 7a [2] 5a 70 [2] 4d 7b [2] 56 35 [2] 6b }

  condition:
    any of them
}