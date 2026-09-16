rule TTP_XOR_MULT_DOSStub_61e1 {
  strings:
    $key_61e1 = { 35 89 [2] 41 91 [2] 06 93 [2] 41 82 [2] 0f 8e [2] 03 84 [2] 14 8f [2] 0f c1 [2] 32 }

  condition:
    any of them
}