rule TTP_XOR_MULT_DOSStub_c0fa {
  strings:
    $key_c0fa = { 94 92 [2] e0 8a [2] a7 88 [2] e0 99 [2] ae 95 [2] a2 9f [2] b5 94 [2] ae da [2] 93 }

  condition:
    any of them
}