rule TTP_XOR_MULT_DOSStub_0835 {
  strings:
    $key_0835 = { 5c 5d [2] 28 45 [2] 6f 47 [2] 28 56 [2] 66 5a [2] 6a 50 [2] 7d 5b [2] 66 15 [2] 5b }

  condition:
    any of them
}