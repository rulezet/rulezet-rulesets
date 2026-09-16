rule TTP_XOR_MULT_DOSStub_c318 {
  strings:
    $key_c318 = { 97 70 [2] e3 68 [2] a4 6a [2] e3 7b [2] ad 77 [2] a1 7d [2] b6 76 [2] ad 38 [2] 90 }

  condition:
    any of them
}