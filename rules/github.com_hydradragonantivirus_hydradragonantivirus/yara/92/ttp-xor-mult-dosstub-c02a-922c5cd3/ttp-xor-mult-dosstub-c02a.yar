rule TTP_XOR_MULT_DOSStub_c02a {
  strings:
    $key_c02a = { 94 42 [2] e0 5a [2] a7 58 [2] e0 49 [2] ae 45 [2] a2 4f [2] b5 44 [2] ae 0a [2] 93 }

  condition:
    any of them
}