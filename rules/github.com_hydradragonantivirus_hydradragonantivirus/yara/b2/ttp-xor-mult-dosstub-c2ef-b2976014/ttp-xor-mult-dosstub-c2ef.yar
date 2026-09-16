rule TTP_XOR_MULT_DOSStub_c2ef {
  strings:
    $key_c2ef = { 96 87 [2] e2 9f [2] a5 9d [2] e2 8c [2] ac 80 [2] a0 8a [2] b7 81 [2] ac cf [2] 91 }

  condition:
    any of them
}