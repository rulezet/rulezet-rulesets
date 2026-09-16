rule TTP_XOR_MULT_DOSStub_c128 {
  strings:
    $key_c128 = { 95 40 [2] e1 58 [2] a6 5a [2] e1 4b [2] af 47 [2] a3 4d [2] b4 46 [2] af 08 [2] 92 }

  condition:
    any of them
}