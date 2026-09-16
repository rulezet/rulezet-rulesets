rule TTP_XOR_MULT_DOSStub_3109 {
  strings:
    $key_3109 = { 65 61 [2] 11 79 [2] 56 7b [2] 11 6a [2] 5f 66 [2] 53 6c [2] 44 67 [2] 5f 29 [2] 62 }

  condition:
    any of them
}