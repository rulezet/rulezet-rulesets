rule TTP_XOR_MULT_DOSStub_c579 {
  strings:
    $key_c579 = { 91 11 [2] e5 09 [2] a2 0b [2] e5 1a [2] ab 16 [2] a7 1c [2] b0 17 [2] ab 59 [2] 96 }

  condition:
    any of them
}