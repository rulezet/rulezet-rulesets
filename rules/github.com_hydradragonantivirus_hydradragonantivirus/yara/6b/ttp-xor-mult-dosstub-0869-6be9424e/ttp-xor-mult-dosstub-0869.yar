rule TTP_XOR_MULT_DOSStub_0869 {
  strings:
    $key_0869 = { 5c 01 [2] 28 19 [2] 6f 1b [2] 28 0a [2] 66 06 [2] 6a 0c [2] 7d 07 [2] 66 49 [2] 5b }

  condition:
    any of them
}