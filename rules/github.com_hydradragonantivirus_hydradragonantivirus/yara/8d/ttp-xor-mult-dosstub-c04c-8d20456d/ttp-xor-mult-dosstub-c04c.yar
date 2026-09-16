rule TTP_XOR_MULT_DOSStub_c04c {
  strings:
    $key_c04c = { 94 24 [2] e0 3c [2] a7 3e [2] e0 2f [2] ae 23 [2] a2 29 [2] b5 22 [2] ae 6c [2] 93 }

  condition:
    any of them
}