rule TTP_XOR_MULT_DOSStub_c406 {
  strings:
    $key_c406 = { 90 6e [2] e4 76 [2] a3 74 [2] e4 65 [2] aa 69 [2] a6 63 [2] b1 68 [2] aa 26 [2] 97 }

  condition:
    any of them
}