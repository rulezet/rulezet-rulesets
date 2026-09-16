rule TTP_XOR_MULT_DOSStub_c74c {
  strings:
    $key_c74c = { 93 24 [2] e7 3c [2] a0 3e [2] e7 2f [2] a9 23 [2] a5 29 [2] b2 22 [2] a9 6c [2] 94 }

  condition:
    any of them
}