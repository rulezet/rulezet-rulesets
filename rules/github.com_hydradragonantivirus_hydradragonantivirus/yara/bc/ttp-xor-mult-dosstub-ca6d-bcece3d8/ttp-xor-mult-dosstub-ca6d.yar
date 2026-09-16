rule TTP_XOR_MULT_DOSStub_ca6d {
  strings:
    $key_ca6d = { 9e 05 [2] ea 1d [2] ad 1f [2] ea 0e [2] a4 02 [2] a8 08 [2] bf 03 [2] a4 4d [2] 99 }

  condition:
    any of them
}