rule TTP_XOR_MULT_DOSStub_c508 {
  strings:
    $key_c508 = { 91 60 [2] e5 78 [2] a2 7a [2] e5 6b [2] ab 67 [2] a7 6d [2] b0 66 [2] ab 28 [2] 96 }

  condition:
    any of them
}