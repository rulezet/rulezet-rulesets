rule TTP_XOR_MULT_DOSStub_c305 {
  strings:
    $key_c305 = { 97 6d [2] e3 75 [2] a4 77 [2] e3 66 [2] ad 6a [2] a1 60 [2] b6 6b [2] ad 25 [2] 90 }

  condition:
    any of them
}