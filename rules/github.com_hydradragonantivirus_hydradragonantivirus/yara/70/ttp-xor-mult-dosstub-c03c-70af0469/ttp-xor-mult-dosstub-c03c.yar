rule TTP_XOR_MULT_DOSStub_c03c {
  strings:
    $key_c03c = { 94 54 [2] e0 4c [2] a7 4e [2] e0 5f [2] ae 53 [2] a2 59 [2] b5 52 [2] ae 1c [2] 93 }

  condition:
    any of them
}