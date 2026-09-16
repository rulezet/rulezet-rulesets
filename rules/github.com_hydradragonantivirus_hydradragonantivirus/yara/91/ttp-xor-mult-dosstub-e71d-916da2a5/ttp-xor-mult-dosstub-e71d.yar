rule TTP_XOR_MULT_DOSStub_e71d {
  strings:
    $key_e71d = { b3 75 [2] c7 6d [2] 80 6f [2] c7 7e [2] 89 72 [2] 85 78 [2] 92 73 [2] 89 3d [2] b4 }

  condition:
    any of them
}