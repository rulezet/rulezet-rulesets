rule TTP_XOR_MULT_DOSStub_3839 {
  strings:
    $key_3839 = { 6c 51 [2] 18 49 [2] 5f 4b [2] 18 5a [2] 56 56 [2] 5a 5c [2] 4d 57 [2] 56 19 [2] 6b }

  condition:
    any of them
}