rule TTP_XOR_MULT_DOSStub_c548 {
  strings:
    $key_c548 = { 91 20 [2] e5 38 [2] a2 3a [2] e5 2b [2] ab 27 [2] a7 2d [2] b0 26 [2] ab 68 [2] 96 }

  condition:
    any of them
}