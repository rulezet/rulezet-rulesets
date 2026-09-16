rule TTP_XOR_MULT_DOSStub_3869 {
  strings:
    $key_3869 = { 6c 01 [2] 18 19 [2] 5f 1b [2] 18 0a [2] 56 06 [2] 5a 0c [2] 4d 07 [2] 56 49 [2] 6b }

  condition:
    any of them
}