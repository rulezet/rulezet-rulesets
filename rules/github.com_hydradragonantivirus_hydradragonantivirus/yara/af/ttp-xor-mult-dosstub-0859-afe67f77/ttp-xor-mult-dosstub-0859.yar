rule TTP_XOR_MULT_DOSStub_0859 {
  strings:
    $key_0859 = { 5c 31 [2] 28 29 [2] 6f 2b [2] 28 3a [2] 66 36 [2] 6a 3c [2] 7d 37 [2] 66 79 [2] 5b }

  condition:
    any of them
}