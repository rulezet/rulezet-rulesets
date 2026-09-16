rule TTP_XOR_MULT_DOSStub_e326 {
  strings:
    $key_e326 = { b7 4e [2] c3 56 [2] 84 54 [2] c3 45 [2] 8d 49 [2] 81 43 [2] 96 48 [2] 8d 06 [2] b0 }

  condition:
    any of them
}