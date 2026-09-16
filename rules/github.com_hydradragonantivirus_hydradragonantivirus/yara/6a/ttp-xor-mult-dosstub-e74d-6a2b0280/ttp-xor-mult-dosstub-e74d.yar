rule TTP_XOR_MULT_DOSStub_e74d {
  strings:
    $key_e74d = { b3 25 [2] c7 3d [2] 80 3f [2] c7 2e [2] 89 22 [2] 85 28 [2] 92 23 [2] 89 6d [2] b4 }

  condition:
    any of them
}