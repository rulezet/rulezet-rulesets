rule TTP_XOR_MULT_DOSStub_2256 {
  strings:
    $key_2256 = { 76 3e [2] 02 26 [2] 45 24 [2] 02 35 [2] 4c 39 [2] 40 33 [2] 57 38 [2] 4c 76 [2] 71 }

  condition:
    any of them
}