rule TTP_XOR_MULT_DOSStub_e10e {
  strings:
    $key_e10e = { b5 66 [2] c1 7e [2] 86 7c [2] c1 6d [2] 8f 61 [2] 83 6b [2] 94 60 [2] 8f 2e [2] b2 }

  condition:
    any of them
}