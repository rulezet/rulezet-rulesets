rule TTP_XOR_MULT_DOSStub_11e0 {
  strings:
    $key_11e0 = { 45 88 [2] 31 90 [2] 76 92 [2] 31 83 [2] 7f 8f [2] 73 85 [2] 64 8e [2] 7f c0 [2] 42 }

  condition:
    any of them
}