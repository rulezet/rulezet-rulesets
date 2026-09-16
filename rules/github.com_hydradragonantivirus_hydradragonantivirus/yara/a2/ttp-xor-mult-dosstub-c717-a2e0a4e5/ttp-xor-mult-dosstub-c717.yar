rule TTP_XOR_MULT_DOSStub_c717 {
  strings:
    $key_c717 = { 93 7f [2] e7 67 [2] a0 65 [2] e7 74 [2] a9 78 [2] a5 72 [2] b2 79 [2] a9 37 [2] 94 }

  condition:
    any of them
}