rule TTP_XOR_MULT_DOSStub_c473 {
  strings:
    $key_c473 = { 90 1b [2] e4 03 [2] a3 01 [2] e4 10 [2] aa 1c [2] a6 16 [2] b1 1d [2] aa 53 [2] 97 }

  condition:
    any of them
}