rule TTP_XOR_MULT_DOSStub_c563 {
  strings:
    $key_c563 = { 91 0b [2] e5 13 [2] a2 11 [2] e5 00 [2] ab 0c [2] a7 06 [2] b0 0d [2] ab 43 [2] 96 }

  condition:
    any of them
}