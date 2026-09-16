rule TTP_XOR_MULT_DOSStub_c178 {
  strings:
    $key_c178 = { 95 10 [2] e1 08 [2] a6 0a [2] e1 1b [2] af 17 [2] a3 1d [2] b4 16 [2] af 58 [2] 92 }

  condition:
    any of them
}