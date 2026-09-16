rule TTP_XOR_MULT_DOSStub_e671 {
  strings:
    $key_e671 = { b2 19 [2] c6 01 [2] 81 03 [2] c6 12 [2] 88 1e [2] 84 14 [2] 93 1f [2] 88 51 [2] b5 }

  condition:
    any of them
}