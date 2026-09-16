rule TTP_XOR_MULT_DOSStub_ca3d {
  strings:
    $key_ca3d = { 9e 55 [2] ea 4d [2] ad 4f [2] ea 5e [2] a4 52 [2] a8 58 [2] bf 53 [2] a4 1d [2] 99 }

  condition:
    any of them
}