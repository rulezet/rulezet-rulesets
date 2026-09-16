rule TTP_XOR_MULT_DOSStub_c0ef {
  strings:
    $key_c0ef = { 94 87 [2] e0 9f [2] a7 9d [2] e0 8c [2] ae 80 [2] a2 8a [2] b5 81 [2] ae cf [2] 93 }

  condition:
    any of them
}