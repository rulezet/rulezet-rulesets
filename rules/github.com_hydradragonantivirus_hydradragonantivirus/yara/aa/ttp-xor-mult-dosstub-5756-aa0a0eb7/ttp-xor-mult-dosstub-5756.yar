rule TTP_XOR_MULT_DOSStub_5756 {
  strings:
    $key_5756 = { 03 3e [2] 77 26 [2] 30 24 [2] 77 35 [2] 39 39 [2] 35 33 [2] 22 38 [2] 39 76 [2] 04 }

  condition:
    any of them
}