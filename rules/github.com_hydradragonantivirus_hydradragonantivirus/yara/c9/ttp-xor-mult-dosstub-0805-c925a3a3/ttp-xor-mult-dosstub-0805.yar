rule TTP_XOR_MULT_DOSStub_0805 {
  strings:
    $key_0805 = { 5c 6d [2] 28 75 [2] 6f 77 [2] 28 66 [2] 66 6a [2] 6a 60 [2] 7d 6b [2] 66 25 [2] 5b }

  condition:
    any of them
}