rule TTP_XOR_MULT_DOSStub_0856 {
  strings:
    $key_0856 = { 5c 3e [2] 28 26 [2] 6f 24 [2] 28 35 [2] 66 39 [2] 6a 33 [2] 7d 38 [2] 66 76 [2] 5b }

  condition:
    any of them
}