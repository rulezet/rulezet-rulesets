rule TTP_XOR_MULT_DOSStub_e47d {
  strings:
    $key_e47d = { b0 15 [2] c4 0d [2] 83 0f [2] c4 1e [2] 8a 12 [2] 86 18 [2] 91 13 [2] 8a 5d [2] b7 }

  condition:
    any of them
}