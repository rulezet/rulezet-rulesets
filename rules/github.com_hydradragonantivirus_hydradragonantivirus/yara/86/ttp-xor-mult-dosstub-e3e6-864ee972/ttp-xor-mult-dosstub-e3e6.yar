rule TTP_XOR_MULT_DOSStub_e3e6 {
  strings:
    $key_e3e6 = { b7 8e [2] c3 96 [2] 84 94 [2] c3 85 [2] 8d 89 [2] 81 83 [2] 96 88 [2] 8d c6 [2] b0 }

  condition:
    any of them
}