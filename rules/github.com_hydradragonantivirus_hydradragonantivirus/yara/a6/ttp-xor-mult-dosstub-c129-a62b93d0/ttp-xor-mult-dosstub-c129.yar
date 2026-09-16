rule TTP_XOR_MULT_DOSStub_c129 {
  strings:
    $key_c129 = { 95 41 [2] e1 59 [2] a6 5b [2] e1 4a [2] af 46 [2] a3 4c [2] b4 47 [2] af 09 [2] 92 }

  condition:
    any of them
}