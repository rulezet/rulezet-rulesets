rule TTP_XOR_MULT_DOSStub_e12d {
  strings:
    $key_e12d = { b5 45 [2] c1 5d [2] 86 5f [2] c1 4e [2] 8f 42 [2] 83 48 [2] 94 43 [2] 8f 0d [2] b2 }

  condition:
    any of them
}