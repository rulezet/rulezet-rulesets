rule TTP_XOR_MULT_DOSStub_01e1 {
  strings:
    $key_01e1 = { 55 89 [2] 21 91 [2] 66 93 [2] 21 82 [2] 6f 8e [2] 63 84 [2] 74 8f [2] 6f c1 [2] 52 }

  condition:
    any of them
}