rule TTP_XOR_MULT_DOSStub_e160 {
  strings:
    $key_e160 = { b5 08 [2] c1 10 [2] 86 12 [2] c1 03 [2] 8f 0f [2] 83 05 [2] 94 0e [2] 8f 40 [2] b2 }

  condition:
    any of them
}