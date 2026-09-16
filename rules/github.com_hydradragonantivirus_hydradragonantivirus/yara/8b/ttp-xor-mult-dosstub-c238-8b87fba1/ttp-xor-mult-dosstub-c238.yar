rule TTP_XOR_MULT_DOSStub_c238 {
  strings:
    $key_c238 = { 96 50 [2] e2 48 [2] a5 4a [2] e2 5b [2] ac 57 [2] a0 5d [2] b7 56 [2] ac 18 [2] 91 }

  condition:
    any of them
}