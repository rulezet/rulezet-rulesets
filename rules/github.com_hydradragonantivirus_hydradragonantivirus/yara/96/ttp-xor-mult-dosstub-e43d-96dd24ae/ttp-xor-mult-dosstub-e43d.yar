rule TTP_XOR_MULT_DOSStub_e43d {
  strings:
    $key_e43d = { b0 55 [2] c4 4d [2] 83 4f [2] c4 5e [2] 8a 52 [2] 86 58 [2] 91 53 [2] 8a 1d [2] b7 }

  condition:
    any of them
}