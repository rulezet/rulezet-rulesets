rule TTP_XOR_MULT_DOSStub_c50d {
  strings:
    $key_c50d = { 91 65 [2] e5 7d [2] a2 7f [2] e5 6e [2] ab 62 [2] a7 68 [2] b0 63 [2] ab 2d [2] 96 }

  condition:
    any of them
}