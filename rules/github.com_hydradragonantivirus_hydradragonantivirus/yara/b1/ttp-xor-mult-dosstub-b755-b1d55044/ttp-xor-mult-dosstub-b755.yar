rule TTP_XOR_MULT_DOSStub_b755 {
  strings:
    $key_b755 = { e3 3d [2] 97 25 [2] d0 27 [2] 97 36 [2] d9 3a [2] d5 30 [2] c2 3b [2] d9 75 [2] e4 }

  condition:
    any of them
}