rule TTP_XOR_MULT_DOSStub_c574 {
  strings:
    $key_c574 = { 91 1c [2] e5 04 [2] a2 06 [2] e5 17 [2] ab 1b [2] a7 11 [2] b0 1a [2] ab 54 [2] 96 }

  condition:
    any of them
}