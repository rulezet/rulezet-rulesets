rule TTP_XOR_MULT_DOSStub_c2e9 {
  strings:
    $key_c2e9 = { 96 81 [2] e2 99 [2] a5 9b [2] e2 8a [2] ac 86 [2] a0 8c [2] b7 87 [2] ac c9 [2] 91 }

  condition:
    any of them
}