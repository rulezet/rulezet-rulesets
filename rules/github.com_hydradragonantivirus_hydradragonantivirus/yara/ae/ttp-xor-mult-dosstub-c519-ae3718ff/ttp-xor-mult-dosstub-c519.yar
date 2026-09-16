rule TTP_XOR_MULT_DOSStub_c519 {
  strings:
    $key_c519 = { 91 71 [2] e5 69 [2] a2 6b [2] e5 7a [2] ab 76 [2] a7 7c [2] b0 77 [2] ab 39 [2] 96 }

  condition:
    any of them
}