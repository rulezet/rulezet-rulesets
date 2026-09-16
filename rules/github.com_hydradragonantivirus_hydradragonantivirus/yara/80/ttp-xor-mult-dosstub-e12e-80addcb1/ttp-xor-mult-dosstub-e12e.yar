rule TTP_XOR_MULT_DOSStub_e12e {
  strings:
    $key_e12e = { b5 46 [2] c1 5e [2] 86 5c [2] c1 4d [2] 8f 41 [2] 83 4b [2] 94 40 [2] 8f 0e [2] b2 }

  condition:
    any of them
}