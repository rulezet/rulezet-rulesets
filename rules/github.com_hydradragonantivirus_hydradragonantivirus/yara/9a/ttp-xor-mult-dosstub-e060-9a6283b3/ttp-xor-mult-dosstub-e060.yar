rule TTP_XOR_MULT_DOSStub_e060 {
  strings:
    $key_e060 = { b4 08 [2] c0 10 [2] 87 12 [2] c0 03 [2] 8e 0f [2] 82 05 [2] 95 0e [2] 8e 40 [2] b3 }

  condition:
    any of them
}