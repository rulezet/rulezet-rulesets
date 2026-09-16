rule TTP_XOR_MULT_DOSStub_e05e {
  strings:
    $key_e05e = { b4 36 [2] c0 2e [2] 87 2c [2] c0 3d [2] 8e 31 [2] 82 3b [2] 95 30 [2] 8e 7e [2] b3 }

  condition:
    any of them
}