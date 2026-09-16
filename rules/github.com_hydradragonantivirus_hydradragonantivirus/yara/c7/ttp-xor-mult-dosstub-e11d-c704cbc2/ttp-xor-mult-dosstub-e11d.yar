rule TTP_XOR_MULT_DOSStub_e11d {
  strings:
    $key_e11d = { b5 75 [2] c1 6d [2] 86 6f [2] c1 7e [2] 8f 72 [2] 83 78 [2] 94 73 [2] 8f 3d [2] b2 }

  condition:
    any of them
}