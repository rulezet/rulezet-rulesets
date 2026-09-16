rule TTP_XOR_MULT_DOSStub_c02d {
  strings:
    $key_c02d = { 94 45 [2] e0 5d [2] a7 5f [2] e0 4e [2] ae 42 [2] a2 48 [2] b5 43 [2] ae 0d [2] 93 }

  condition:
    any of them
}