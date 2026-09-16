rule TTP_XOR_MULT_DOSStub_e55e {
  strings:
    $key_e55e = { b1 36 [2] c5 2e [2] 82 2c [2] c5 3d [2] 8b 31 [2] 87 3b [2] 90 30 [2] 8b 7e [2] b6 }

  condition:
    any of them
}