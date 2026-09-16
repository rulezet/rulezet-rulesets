rule TTP_XOR_MULT_DOSStub_c0e0 {
  strings:
    $key_c0e0 = { 94 88 [2] e0 90 [2] a7 92 [2] e0 83 [2] ae 8f [2] a2 85 [2] b5 8e [2] ae c0 [2] 93 }

  condition:
    any of them
}