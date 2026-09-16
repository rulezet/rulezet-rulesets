rule TTP_XOR_MULT_DOSStub_e266 {
  strings:
    $key_e266 = { b6 0e [2] c2 16 [2] 85 14 [2] c2 05 [2] 8c 09 [2] 80 03 [2] 97 08 [2] 8c 46 [2] b1 }

  condition:
    any of them
}