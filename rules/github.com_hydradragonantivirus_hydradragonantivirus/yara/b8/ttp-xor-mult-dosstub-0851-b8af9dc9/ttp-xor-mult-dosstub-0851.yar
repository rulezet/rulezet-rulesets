rule TTP_XOR_MULT_DOSStub_0851 {
  strings:
    $key_0851 = { 5c 39 [2] 28 21 [2] 6f 23 [2] 28 32 [2] 66 3e [2] 6a 34 [2] 7d 3f [2] 66 71 [2] 5b }

  condition:
    any of them
}