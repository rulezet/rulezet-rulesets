rule TTP_XOR_MULT_DOSStub_c552 {
  strings:
    $key_c552 = { 91 3a [2] e5 22 [2] a2 20 [2] e5 31 [2] ab 3d [2] a7 37 [2] b0 3c [2] ab 72 [2] 96 }

  condition:
    any of them
}