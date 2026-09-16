rule TTP_XOR_MULT_DOSStub_e611 {
  strings:
    $key_e611 = { b2 79 [2] c6 61 [2] 81 63 [2] c6 72 [2] 88 7e [2] 84 74 [2] 93 7f [2] 88 31 [2] b5 }

  condition:
    any of them
}