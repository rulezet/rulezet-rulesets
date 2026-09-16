rule TTP_XOR_MULT_DOSStub_f443 {
  strings:
    $key_f443 = { a0 2b [2] d4 33 [2] 93 31 [2] d4 20 [2] 9a 2c [2] 96 26 [2] 81 2d [2] 9a 63 [2] a7 }

  condition:
    any of them
}