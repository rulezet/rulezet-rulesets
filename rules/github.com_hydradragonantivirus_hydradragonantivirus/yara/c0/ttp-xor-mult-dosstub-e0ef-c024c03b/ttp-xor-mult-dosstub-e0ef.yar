rule TTP_XOR_MULT_DOSStub_e0ef {
  strings:
    $key_e0ef = { b4 87 [2] c0 9f [2] 87 9d [2] c0 8c [2] 8e 80 [2] 82 8a [2] 95 81 [2] 8e cf [2] b3 }

  condition:
    any of them
}