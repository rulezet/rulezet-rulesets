rule TTP_XOR_MULT_DOSStub_c0e5 {
  strings:
    $key_c0e5 = { 94 8d [2] e0 95 [2] a7 97 [2] e0 86 [2] ae 8a [2] a2 80 [2] b5 8b [2] ae c5 [2] 93 }

  condition:
    any of them
}