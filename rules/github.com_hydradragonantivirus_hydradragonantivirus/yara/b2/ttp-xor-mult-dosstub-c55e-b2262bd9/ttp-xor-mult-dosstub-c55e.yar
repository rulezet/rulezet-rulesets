rule TTP_XOR_MULT_DOSStub_c55e {
  strings:
    $key_c55e = { 91 36 [2] e5 2e [2] a2 2c [2] e5 3d [2] ab 31 [2] a7 3b [2] b0 30 [2] ab 7e [2] 96 }

  condition:
    any of them
}