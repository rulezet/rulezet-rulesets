rule TTP_XOR_MULT_DOSStub_b301 {
  strings:
    $key_b301 = { e7 69 [2] 93 71 [2] d4 73 [2] 93 62 [2] dd 6e [2] d1 64 [2] c6 6f [2] dd 21 [2] e0 }

  condition:
    any of them
}