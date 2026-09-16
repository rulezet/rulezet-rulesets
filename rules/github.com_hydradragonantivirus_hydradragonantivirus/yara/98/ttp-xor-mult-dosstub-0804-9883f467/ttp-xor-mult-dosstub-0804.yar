rule TTP_XOR_MULT_DOSStub_0804 {
  strings:
    $key_0804 = { 5c 6c [2] 28 74 [2] 6f 76 [2] 28 67 [2] 66 6b [2] 6a 61 [2] 7d 6a [2] 66 24 [2] 5b }

  condition:
    any of them
}