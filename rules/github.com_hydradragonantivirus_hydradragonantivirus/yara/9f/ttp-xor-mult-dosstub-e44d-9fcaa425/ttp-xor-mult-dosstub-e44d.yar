rule TTP_XOR_MULT_DOSStub_e44d {
  strings:
    $key_e44d = { b0 25 [2] c4 3d [2] 83 3f [2] c4 2e [2] 8a 22 [2] 86 28 [2] 91 23 [2] 8a 6d [2] b7 }

  condition:
    any of them
}