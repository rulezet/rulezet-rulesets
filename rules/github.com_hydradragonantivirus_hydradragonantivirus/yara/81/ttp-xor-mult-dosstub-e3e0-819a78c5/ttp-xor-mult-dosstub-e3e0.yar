rule TTP_XOR_MULT_DOSStub_e3e0 {
  strings:
    $key_e3e0 = { b7 88 [2] c3 90 [2] 84 92 [2] c3 83 [2] 8d 8f [2] 81 85 [2] 96 8e [2] 8d c0 [2] b0 }

  condition:
    any of them
}