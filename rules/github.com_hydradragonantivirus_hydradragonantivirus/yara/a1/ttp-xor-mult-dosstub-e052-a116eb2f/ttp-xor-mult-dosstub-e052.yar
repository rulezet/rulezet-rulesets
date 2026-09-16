rule TTP_XOR_MULT_DOSStub_e052 {
  strings:
    $key_e052 = { b4 3a [2] c0 22 [2] 87 20 [2] c0 31 [2] 8e 3d [2] 82 37 [2] 95 3c [2] 8e 72 [2] b3 }

  condition:
    any of them
}