rule TTP_XOR_MULT_DOSStub_c30d {
  strings:
    $key_c30d = { 97 65 [2] e3 7d [2] a4 7f [2] e3 6e [2] ad 62 [2] a1 68 [2] b6 63 [2] ad 2d [2] 90 }

  condition:
    any of them
}