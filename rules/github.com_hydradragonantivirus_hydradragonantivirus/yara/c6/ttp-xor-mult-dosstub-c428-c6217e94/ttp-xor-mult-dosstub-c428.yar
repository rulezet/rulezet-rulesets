rule TTP_XOR_MULT_DOSStub_c428 {
  strings:
    $key_c428 = { 90 40 [2] e4 58 [2] a3 5a [2] e4 4b [2] aa 47 [2] a6 4d [2] b1 46 [2] aa 08 [2] 97 }

  condition:
    any of them
}