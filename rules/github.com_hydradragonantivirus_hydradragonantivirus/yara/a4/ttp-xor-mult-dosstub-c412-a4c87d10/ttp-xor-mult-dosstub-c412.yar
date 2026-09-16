rule TTP_XOR_MULT_DOSStub_c412 {
  strings:
    $key_c412 = { 90 7a [2] e4 62 [2] a3 60 [2] e4 71 [2] aa 7d [2] a6 77 [2] b1 7c [2] aa 32 [2] 97 }

  condition:
    any of them
}