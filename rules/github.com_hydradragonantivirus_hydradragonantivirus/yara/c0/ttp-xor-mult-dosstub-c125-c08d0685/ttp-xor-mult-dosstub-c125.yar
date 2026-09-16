rule TTP_XOR_MULT_DOSStub_c125 {
  strings:
    $key_c125 = { 95 4d [2] e1 55 [2] a6 57 [2] e1 46 [2] af 4a [2] a3 40 [2] b4 4b [2] af 05 [2] 92 }

  condition:
    any of them
}