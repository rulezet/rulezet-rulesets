rule TTP_XOR_MULT_DOSStub_21e6 {
  strings:
    $key_21e6 = { 75 8e [2] 01 96 [2] 46 94 [2] 01 85 [2] 4f 89 [2] 43 83 [2] 54 88 [2] 4f c6 [2] 72 }

  condition:
    any of them
}