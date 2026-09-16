rule TTP_XOR_MULT_DOSStub_c165 {
  strings:
    $key_c165 = { 95 0d [2] e1 15 [2] a6 17 [2] e1 06 [2] af 0a [2] a3 00 [2] b4 0b [2] af 45 [2] 92 }

  condition:
    any of them
}