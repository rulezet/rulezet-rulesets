rule TTP_XOR_MULT_DOSStub_c722 {
  strings:
    $key_c722 = { 93 4a [2] e7 52 [2] a0 50 [2] e7 41 [2] a9 4d [2] a5 47 [2] b2 4c [2] a9 02 [2] 94 }

  condition:
    any of them
}