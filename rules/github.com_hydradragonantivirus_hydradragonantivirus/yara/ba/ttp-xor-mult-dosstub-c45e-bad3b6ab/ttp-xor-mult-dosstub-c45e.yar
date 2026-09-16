rule TTP_XOR_MULT_DOSStub_c45e {
  strings:
    $key_c45e = { 90 36 [2] e4 2e [2] a3 2c [2] e4 3d [2] aa 31 [2] a6 3b [2] b1 30 [2] aa 7e [2] 97 }

  condition:
    any of them
}