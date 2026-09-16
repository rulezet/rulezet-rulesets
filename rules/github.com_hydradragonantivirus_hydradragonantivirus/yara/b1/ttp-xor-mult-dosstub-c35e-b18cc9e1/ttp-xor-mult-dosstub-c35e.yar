rule TTP_XOR_MULT_DOSStub_c35e {
  strings:
    $key_c35e = { 97 36 [2] e3 2e [2] a4 2c [2] e3 3d [2] ad 31 [2] a1 3b [2] b6 30 [2] ad 7e [2] 90 }

  condition:
    any of them
}