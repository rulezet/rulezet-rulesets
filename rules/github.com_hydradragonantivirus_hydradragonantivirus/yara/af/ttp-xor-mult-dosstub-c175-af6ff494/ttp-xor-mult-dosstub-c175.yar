rule TTP_XOR_MULT_DOSStub_c175 {
  strings:
    $key_c175 = { 95 1d [2] e1 05 [2] a6 07 [2] e1 16 [2] af 1a [2] a3 10 [2] b4 1b [2] af 55 [2] 92 }

  condition:
    any of them
}