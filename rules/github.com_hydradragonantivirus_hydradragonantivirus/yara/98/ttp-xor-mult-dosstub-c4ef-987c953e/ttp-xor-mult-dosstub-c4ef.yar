rule TTP_XOR_MULT_DOSStub_c4ef {
  strings:
    $key_c4ef = { 90 87 [2] e4 9f [2] a3 9d [2] e4 8c [2] aa 80 [2] a6 8a [2] b1 81 [2] aa cf [2] 97 }

  condition:
    any of them
}