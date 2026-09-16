rule TTP_XOR_MULT_DOSStub_c5fa {
  strings:
    $key_c5fa = { 91 92 [2] e5 8a [2] a2 88 [2] e5 99 [2] ab 95 [2] a7 9f [2] b0 94 [2] ab da [2] 96 }

  condition:
    any of them
}