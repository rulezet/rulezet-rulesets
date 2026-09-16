rule TTP_XOR_MULT_DOSStub_c205 {
  strings:
    $key_c205 = { 96 6d [2] e2 75 [2] a5 77 [2] e2 66 [2] ac 6a [2] a0 60 [2] b7 6b [2] ac 25 [2] 91 }

  condition:
    any of them
}