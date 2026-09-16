rule TTP_XOR_MULT_DOSStub_c060 {
  strings:
    $key_c060 = { 94 08 [2] e0 10 [2] a7 12 [2] e0 03 [2] ae 0f [2] a2 05 [2] b5 0e [2] ae 40 [2] 93 }

  condition:
    any of them
}