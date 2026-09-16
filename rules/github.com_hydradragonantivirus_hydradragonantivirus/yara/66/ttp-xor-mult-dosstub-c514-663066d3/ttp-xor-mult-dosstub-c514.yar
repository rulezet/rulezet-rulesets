rule TTP_XOR_MULT_DOSStub_c514 {
  strings:
    $key_c514 = { 91 7c [2] e5 64 [2] a2 66 [2] e5 77 [2] ab 7b [2] a7 71 [2] b0 7a [2] ab 34 [2] 96 }

  condition:
    any of them
}