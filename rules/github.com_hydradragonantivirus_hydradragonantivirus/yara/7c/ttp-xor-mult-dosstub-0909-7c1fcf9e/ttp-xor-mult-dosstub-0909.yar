rule TTP_XOR_MULT_DOSStub_0909 {
  strings:
    $key_0909 = { 5d 61 [2] 29 79 [2] 6e 7b [2] 29 6a [2] 67 66 [2] 6b 6c [2] 7c 67 [2] 67 29 [2] 5a }

  condition:
    any of them
}