rule TTP_XOR_MULT_DOSStub_0870 {
  strings:
    $key_0870 = { 5c 18 [2] 28 00 [2] 6f 02 [2] 28 13 [2] 66 1f [2] 6a 15 [2] 7d 1e [2] 66 50 [2] 5b }

  condition:
    any of them
}