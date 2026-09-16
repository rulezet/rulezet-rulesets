rule TTP_XOR_MULT_DOSStub_c352 {
  strings:
    $key_c352 = { 97 3a [2] e3 22 [2] a4 20 [2] e3 31 [2] ad 3d [2] a1 37 [2] b6 3c [2] ad 72 [2] 90 }

  condition:
    any of them
}