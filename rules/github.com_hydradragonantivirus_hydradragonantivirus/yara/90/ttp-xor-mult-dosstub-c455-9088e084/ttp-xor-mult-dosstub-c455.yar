rule TTP_XOR_MULT_DOSStub_c455 {
  strings:
    $key_c455 = { 90 3d [2] e4 25 [2] a3 27 [2] e4 36 [2] aa 3a [2] a6 30 [2] b1 3b [2] aa 75 [2] 97 }

  condition:
    any of them
}