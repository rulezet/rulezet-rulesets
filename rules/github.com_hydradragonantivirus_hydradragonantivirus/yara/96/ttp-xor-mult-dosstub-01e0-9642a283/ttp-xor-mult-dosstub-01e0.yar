rule TTP_XOR_MULT_DOSStub_01e0 {
  strings:
    $key_01e0 = { 55 88 [2] 21 90 [2] 66 92 [2] 21 83 [2] 6f 8f [2] 63 85 [2] 74 8e [2] 6f c0 [2] 52 }

  condition:
    any of them
}