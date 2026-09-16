rule TTP_XOR_MULT_DOSStub_c3ef {
  strings:
    $key_c3ef = { 97 87 [2] e3 9f [2] a4 9d [2] e3 8c [2] ad 80 [2] a1 8a [2] b6 81 [2] ad cf [2] 90 }

  condition:
    any of them
}