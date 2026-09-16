rule TTP_XOR_MULT_DOSStub_51e0 {
  strings:
    $key_51e0 = { 05 88 [2] 71 90 [2] 36 92 [2] 71 83 [2] 3f 8f [2] 33 85 [2] 24 8e [2] 3f c0 [2] 02 }

  condition:
    any of them
}