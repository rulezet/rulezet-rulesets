rule TTP_XOR_MULT_DOSStub_c71c {
  strings:
    $key_c71c = { 93 74 [2] e7 6c [2] a0 6e [2] e7 7f [2] a9 73 [2] a5 79 [2] b2 72 [2] a9 3c [2] 94 }

  condition:
    any of them
}