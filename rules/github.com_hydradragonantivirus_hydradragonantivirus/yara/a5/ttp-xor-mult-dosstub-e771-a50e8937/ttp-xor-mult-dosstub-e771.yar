rule TTP_XOR_MULT_DOSStub_e771 {
  strings:
    $key_e771 = { b3 19 [2] c7 01 [2] 80 03 [2] c7 12 [2] 89 1e [2] 85 14 [2] 92 1f [2] 89 51 [2] b4 }

  condition:
    any of them
}