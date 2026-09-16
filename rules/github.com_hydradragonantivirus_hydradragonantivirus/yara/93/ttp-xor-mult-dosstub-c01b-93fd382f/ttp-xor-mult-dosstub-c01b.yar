rule TTP_XOR_MULT_DOSStub_c01b {
  strings:
    $key_c01b = { 94 73 [2] e0 6b [2] a7 69 [2] e0 78 [2] ae 74 [2] a2 7e [2] b5 75 [2] ae 3b [2] 93 }

  condition:
    any of them
}