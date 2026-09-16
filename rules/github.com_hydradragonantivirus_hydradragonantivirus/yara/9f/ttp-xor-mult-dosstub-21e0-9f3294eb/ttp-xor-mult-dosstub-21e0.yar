rule TTP_XOR_MULT_DOSStub_21e0 {
  strings:
    $key_21e0 = { 75 88 [2] 01 90 [2] 46 92 [2] 01 83 [2] 4f 8f [2] 43 85 [2] 54 8e [2] 4f c0 [2] 72 }

  condition:
    any of them
}