rule TTP_XOR_MULT_DOSStub_e161 {
  strings:
    $key_e161 = { b5 09 [2] c1 11 [2] 86 13 [2] c1 02 [2] 8f 0e [2] 83 04 [2] 94 0f [2] 8f 41 [2] b2 }

  condition:
    any of them
}