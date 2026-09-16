rule TTP_XOR_MULT_DOSStub_c1ef {
  strings:
    $key_c1ef = { 95 87 [2] e1 9f [2] a6 9d [2] e1 8c [2] af 80 [2] a3 8a [2] b4 81 [2] af cf [2] 92 }

  condition:
    any of them
}