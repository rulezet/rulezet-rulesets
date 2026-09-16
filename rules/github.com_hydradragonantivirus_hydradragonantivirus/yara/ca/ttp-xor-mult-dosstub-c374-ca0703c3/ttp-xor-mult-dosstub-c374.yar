rule TTP_XOR_MULT_DOSStub_c374 {
  strings:
    $key_c374 = { 97 1c [2] e3 04 [2] a4 06 [2] e3 17 [2] ad 1b [2] a1 11 [2] b6 1a [2] ad 54 [2] 90 }

  condition:
    any of them
}