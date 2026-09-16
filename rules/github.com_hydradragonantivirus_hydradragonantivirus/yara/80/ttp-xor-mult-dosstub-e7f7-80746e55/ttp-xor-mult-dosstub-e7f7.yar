rule TTP_XOR_MULT_DOSStub_e7f7 {
  strings:
    $key_e7f7 = { b3 9f [2] c7 87 [2] 80 85 [2] c7 94 [2] 89 98 [2] 85 92 [2] 92 99 [2] 89 d7 [2] b4 }

  condition:
    any of them
}