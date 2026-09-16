rule TTP_XOR_MULT_DOSStub_e006 {
  strings:
    $key_e006 = { b4 6e [2] c0 76 [2] 87 74 [2] c0 65 [2] 8e 69 [2] 82 63 [2] 95 68 [2] 8e 26 [2] b3 }

  condition:
    any of them
}