rule TTP_XOR_MULT_DOSStub_3138 {
  strings:
    $key_3138 = { 65 50 [2] 11 48 [2] 56 4a [2] 11 5b [2] 5f 57 [2] 53 5d [2] 44 56 [2] 5f 18 [2] 62 }

  condition:
    any of them
}