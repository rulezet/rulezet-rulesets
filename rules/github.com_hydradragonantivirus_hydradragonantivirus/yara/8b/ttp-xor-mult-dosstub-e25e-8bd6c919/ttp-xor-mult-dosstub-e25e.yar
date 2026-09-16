rule TTP_XOR_MULT_DOSStub_e25e {
  strings:
    $key_e25e = { b6 36 [2] c2 2e [2] 85 2c [2] c2 3d [2] 8c 31 [2] 80 3b [2] 97 30 [2] 8c 7e [2] b1 }

  condition:
    any of them
}