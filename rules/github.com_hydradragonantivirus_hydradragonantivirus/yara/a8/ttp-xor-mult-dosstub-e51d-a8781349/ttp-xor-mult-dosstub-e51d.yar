rule TTP_XOR_MULT_DOSStub_e51d {
  strings:
    $key_e51d = { b1 75 [2] c5 6d [2] 82 6f [2] c5 7e [2] 8b 72 [2] 87 78 [2] 90 73 [2] 8b 3d [2] b6 }

  condition:
    any of them
}