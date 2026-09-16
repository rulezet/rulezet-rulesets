rule TTP_XOR_MULT_DOSStub_144d {
  strings:
    $key_144d = { 40 25 [2] 34 3d [2] 73 3f [2] 34 2e [2] 7a 22 [2] 76 28 [2] 61 23 [2] 7a 6d [2] 47 }

  condition:
    any of them
}