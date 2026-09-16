rule TTP_XOR_MULT_DOSStub_c15e {
  strings:
    $key_c15e = { 95 36 [2] e1 2e [2] a6 2c [2] e1 3d [2] af 31 [2] a3 3b [2] b4 30 [2] af 7e [2] 92 }

  condition:
    any of them
}