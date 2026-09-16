rule TTP_XOR_MULT_DOSStub_e75e {
  strings:
    $key_e75e = { b3 36 [2] c7 2e [2] 80 2c [2] c7 3d [2] 89 31 [2] 85 3b [2] 92 30 [2] 89 7e [2] b4 }

  condition:
    any of them
}