rule TTP_XOR_MULT_DOSStub_2506 {
  strings:
    $key_2506 = { 71 6e [2] 05 76 [2] 42 74 [2] 05 65 [2] 4b 69 [2] 47 63 [2] 50 68 [2] 4b 26 [2] 76 }

  condition:
    any of them
}