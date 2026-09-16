rule TTP_XOR_MULT_DOSStub_c540 {
  strings:
    $key_c540 = { 91 28 [2] e5 30 [2] a2 32 [2] e5 23 [2] ab 2f [2] a7 25 [2] b0 2e [2] ab 60 [2] 96 }

  condition:
    any of them
}