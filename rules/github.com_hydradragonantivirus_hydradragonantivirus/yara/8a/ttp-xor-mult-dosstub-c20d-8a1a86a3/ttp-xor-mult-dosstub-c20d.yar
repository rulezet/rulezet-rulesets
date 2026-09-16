rule TTP_XOR_MULT_DOSStub_c20d {
  strings:
    $key_c20d = { 96 65 [2] e2 7d [2] a5 7f [2] e2 6e [2] ac 62 [2] a0 68 [2] b7 63 [2] ac 2d [2] 91 }

  condition:
    any of them
}