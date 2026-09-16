rule TTP_XOR_MULT_DOSStub_c564 {
  strings:
    $key_c564 = { 91 0c [2] e5 14 [2] a2 16 [2] e5 07 [2] ab 0b [2] a7 01 [2] b0 0a [2] ab 44 [2] 96 }

  condition:
    any of them
}