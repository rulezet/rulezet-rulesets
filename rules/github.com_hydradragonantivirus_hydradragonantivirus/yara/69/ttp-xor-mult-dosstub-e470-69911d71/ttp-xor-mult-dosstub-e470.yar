rule TTP_XOR_MULT_DOSStub_e470 {
  strings:
    $key_e470 = { b0 18 [2] c4 00 [2] 83 02 [2] c4 13 [2] 8a 1f [2] 86 15 [2] 91 1e [2] 8a 50 [2] b7 }

  condition:
    any of them
}