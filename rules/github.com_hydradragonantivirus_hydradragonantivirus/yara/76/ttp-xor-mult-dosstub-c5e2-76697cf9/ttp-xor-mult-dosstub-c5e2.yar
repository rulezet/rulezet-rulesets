rule TTP_XOR_MULT_DOSStub_c5e2 {
  strings:
    $key_c5e2 = { 91 8a [2] e5 92 [2] a2 90 [2] e5 81 [2] ab 8d [2] a7 87 [2] b0 8c [2] ab c2 [2] 96 }

  condition:
    any of them
}