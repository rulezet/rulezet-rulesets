rule TTP_XOR_MULT_DOSStub_e476 {
  strings:
    $key_e476 = { b0 1e [2] c4 06 [2] 83 04 [2] c4 15 [2] 8a 19 [2] 86 13 [2] 91 18 [2] 8a 56 [2] b7 }

  condition:
    any of them
}