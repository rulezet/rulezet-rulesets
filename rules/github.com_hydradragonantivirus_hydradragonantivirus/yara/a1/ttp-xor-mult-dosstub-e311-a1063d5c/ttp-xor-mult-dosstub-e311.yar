rule TTP_XOR_MULT_DOSStub_e311 {
  strings:
    $key_e311 = { b7 79 [2] c3 61 [2] 84 63 [2] c3 72 [2] 8d 7e [2] 81 74 [2] 96 7f [2] 8d 31 [2] b0 }

  condition:
    any of them
}