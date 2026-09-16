rule TTP_XOR_MULT_DOSStub_e066 {
  strings:
    $key_e066 = { b4 0e [2] c0 16 [2] 87 14 [2] c0 05 [2] 8e 09 [2] 82 03 [2] 95 08 [2] 8e 46 [2] b3 }

  condition:
    any of them
}