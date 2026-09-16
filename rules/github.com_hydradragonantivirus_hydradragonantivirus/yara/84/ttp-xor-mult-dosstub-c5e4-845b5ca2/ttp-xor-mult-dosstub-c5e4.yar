rule TTP_XOR_MULT_DOSStub_c5e4 {
  strings:
    $key_c5e4 = { 91 8c [2] e5 94 [2] a2 96 [2] e5 87 [2] ab 8b [2] a7 81 [2] b0 8a [2] ab c4 [2] 96 }

  condition:
    any of them
}