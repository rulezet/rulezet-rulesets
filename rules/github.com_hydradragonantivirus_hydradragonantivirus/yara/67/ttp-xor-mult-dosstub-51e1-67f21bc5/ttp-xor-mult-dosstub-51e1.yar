rule TTP_XOR_MULT_DOSStub_51e1 {
  strings:
    $key_51e1 = { 05 89 [2] 71 91 [2] 36 93 [2] 71 82 [2] 3f 8e [2] 33 84 [2] 24 8f [2] 3f c1 [2] 02 }

  condition:
    any of them
}