rule TTP_XOR_MULT_DOSStub_c219 {
  strings:
    $key_c219 = { 96 71 [2] e2 69 [2] a5 6b [2] e2 7a [2] ac 76 [2] a0 7c [2] b7 77 [2] ac 39 [2] 91 }

  condition:
    any of them
}