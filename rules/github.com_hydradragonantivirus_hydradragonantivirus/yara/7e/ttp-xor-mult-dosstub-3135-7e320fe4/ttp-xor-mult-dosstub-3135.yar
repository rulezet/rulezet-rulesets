rule TTP_XOR_MULT_DOSStub_3135 {
  strings:
    $key_3135 = { 65 5d [2] 11 45 [2] 56 47 [2] 11 56 [2] 5f 5a [2] 53 50 [2] 44 5b [2] 5f 15 [2] 62 }

  condition:
    any of them
}