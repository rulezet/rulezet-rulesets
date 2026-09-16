rule TTP_XOR_MULT_DOSStub_e73e {
  strings:
    $key_e73e = { b3 56 [2] c7 4e [2] 80 4c [2] c7 5d [2] 89 51 [2] 85 5b [2] 92 50 [2] 89 1e [2] b4 }

  condition:
    any of them
}