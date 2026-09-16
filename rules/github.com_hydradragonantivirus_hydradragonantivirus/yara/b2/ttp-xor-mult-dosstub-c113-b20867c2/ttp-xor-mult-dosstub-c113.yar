rule TTP_XOR_MULT_DOSStub_c113 {
  strings:
    $key_c113 = { 95 7b [2] e1 63 [2] a6 61 [2] e1 70 [2] af 7c [2] a3 76 [2] b4 7d [2] af 33 [2] 92 }

  condition:
    any of them
}