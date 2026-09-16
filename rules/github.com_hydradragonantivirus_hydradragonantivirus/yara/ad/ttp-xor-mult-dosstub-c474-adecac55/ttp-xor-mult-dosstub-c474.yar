rule TTP_XOR_MULT_DOSStub_c474 {
  strings:
    $key_c474 = { 90 1c [2] e4 04 [2] a3 06 [2] e4 17 [2] aa 1b [2] a6 11 [2] b1 1a [2] aa 54 [2] 97 }

  condition:
    any of them
}