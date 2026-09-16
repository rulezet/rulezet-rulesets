rule TTP_XOR_MULT_DOSStub_c545 {
  strings:
    $key_c545 = { 91 2d [2] e5 35 [2] a2 37 [2] e5 26 [2] ab 2a [2] a7 20 [2] b0 2b [2] ab 65 [2] 96 }

  condition:
    any of them
}