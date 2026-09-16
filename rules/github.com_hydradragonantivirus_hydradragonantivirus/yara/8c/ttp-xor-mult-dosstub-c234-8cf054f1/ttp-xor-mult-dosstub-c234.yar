rule TTP_XOR_MULT_DOSStub_c234 {
  strings:
    $key_c234 = { 96 5c [2] e2 44 [2] a5 46 [2] e2 57 [2] ac 5b [2] a0 51 [2] b7 5a [2] ac 14 [2] 91 }

  condition:
    any of them
}