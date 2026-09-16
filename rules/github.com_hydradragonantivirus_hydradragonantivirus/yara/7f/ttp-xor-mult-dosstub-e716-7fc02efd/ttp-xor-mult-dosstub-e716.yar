rule TTP_XOR_MULT_DOSStub_e716 {
  strings:
    $key_e716 = { b3 7e [2] c7 66 [2] 80 64 [2] c7 75 [2] 89 79 [2] 85 73 [2] 92 78 [2] 89 36 [2] b4 }

  condition:
    any of them
}