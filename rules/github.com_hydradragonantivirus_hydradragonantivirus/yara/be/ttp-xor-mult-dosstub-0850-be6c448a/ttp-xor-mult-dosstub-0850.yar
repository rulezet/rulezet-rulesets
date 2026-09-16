rule TTP_XOR_MULT_DOSStub_0850 {
  strings:
    $key_0850 = { 5c 38 [2] 28 20 [2] 6f 22 [2] 28 33 [2] 66 3f [2] 6a 35 [2] 7d 3e [2] 66 70 [2] 5b }

  condition:
    any of them
}