rule TTP_XOR_MULT_DOSStub_a65e {
  strings:
    $key_a65e = { f2 36 [2] 86 2e [2] c1 2c [2] 86 3d [2] c8 31 [2] c4 3b [2] d3 30 [2] c8 7e [2] f5 }

  condition:
    any of them
}