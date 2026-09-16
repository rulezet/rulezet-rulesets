rule TTP_XOR_MULT_DOSStub_3804 {
  strings:
    $key_3804 = { 6c 6c [2] 18 74 [2] 5f 76 [2] 18 67 [2] 56 6b [2] 5a 61 [2] 4d 6a [2] 56 24 [2] 6b }

  condition:
    any of them
}