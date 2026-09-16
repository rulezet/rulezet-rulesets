rule TTP_XOR_MULT_DOSStub_c5f7 {
  strings:
    $key_c5f7 = { 91 9f [2] e5 87 [2] a2 85 [2] e5 94 [2] ab 98 [2] a7 92 [2] b0 99 [2] ab d7 [2] 96 }

  condition:
    any of them
}