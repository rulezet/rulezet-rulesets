rule TTP_XOR_MULT_DOSStub_7256 {
  strings:
    $key_7256 = { 26 3e [2] 52 26 [2] 15 24 [2] 52 35 [2] 1c 39 [2] 10 33 [2] 07 38 [2] 1c 76 [2] 21 }

  condition:
    any of them
}