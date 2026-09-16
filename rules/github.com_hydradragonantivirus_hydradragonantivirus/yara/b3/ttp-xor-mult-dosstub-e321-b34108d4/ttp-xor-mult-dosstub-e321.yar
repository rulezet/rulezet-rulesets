rule TTP_XOR_MULT_DOSStub_e321 {
  strings:
    $key_e321 = { b7 49 [2] c3 51 [2] 84 53 [2] c3 42 [2] 8d 4e [2] 81 44 [2] 96 4f [2] 8d 01 [2] b0 }

  condition:
    any of them
}