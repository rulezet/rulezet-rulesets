rule TTP_XOR_MULT_DOSStub_c4e8 {
  strings:
    $key_c4e8 = { 90 80 [2] e4 98 [2] a3 9a [2] e4 8b [2] aa 87 [2] a6 8d [2] b1 86 [2] aa c8 [2] 97 }

  condition:
    any of them
}