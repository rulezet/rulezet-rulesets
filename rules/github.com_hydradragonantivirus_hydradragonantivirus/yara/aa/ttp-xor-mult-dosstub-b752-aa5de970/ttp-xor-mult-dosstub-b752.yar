rule TTP_XOR_MULT_DOSStub_b752 {
  strings:
    $key_b752 = { e3 3a [2] 97 22 [2] d0 20 [2] 97 31 [2] d9 3d [2] d5 37 [2] c2 3c [2] d9 72 [2] e4 }

  condition:
    any of them
}