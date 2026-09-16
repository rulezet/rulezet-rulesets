rule TTP_XOR_MULT_DOSStub_c249 {
  strings:
    $key_c249 = { 96 21 [2] e2 39 [2] a5 3b [2] e2 2a [2] ac 26 [2] a0 2c [2] b7 27 [2] ac 69 [2] 91 }

  condition:
    any of them
}