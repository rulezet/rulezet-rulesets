rule TTP_XOR_MULT_DOSStub_c5eb {
  strings:
    $key_c5eb = { 91 83 [2] e5 9b [2] a2 99 [2] e5 88 [2] ab 84 [2] a7 8e [2] b0 85 [2] ab cb [2] 96 }

  condition:
    any of them
}