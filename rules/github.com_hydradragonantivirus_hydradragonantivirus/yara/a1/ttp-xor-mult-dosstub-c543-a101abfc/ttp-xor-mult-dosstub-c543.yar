rule TTP_XOR_MULT_DOSStub_c543 {
  strings:
    $key_c543 = { 91 2b [2] e5 33 [2] a2 31 [2] e5 20 [2] ab 2c [2] a7 26 [2] b0 2d [2] ab 63 [2] 96 }

  condition:
    any of them
}