rule TTP_XOR_MULT_DOSStub_e471 {
  strings:
    $key_e471 = { b0 19 [2] c4 01 [2] 83 03 [2] c4 12 [2] 8a 1e [2] 86 14 [2] 91 1f [2] 8a 51 [2] b7 }

  condition:
    any of them
}