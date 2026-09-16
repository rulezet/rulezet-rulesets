rule TTP_XOR_MULT_DOSStub_e306 {
  strings:
    $key_e306 = { b7 6e [2] c3 76 [2] 84 74 [2] c3 65 [2] 8d 69 [2] 81 63 [2] 96 68 [2] 8d 26 [2] b0 }

  condition:
    any of them
}