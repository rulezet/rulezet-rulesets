rule TTP_XOR_MULT_DOSStub_e13e {
  strings:
    $key_e13e = { b5 56 [2] c1 4e [2] 86 4c [2] c1 5d [2] 8f 51 [2] 83 5b [2] 94 50 [2] 8f 1e [2] b2 }

  condition:
    any of them
}