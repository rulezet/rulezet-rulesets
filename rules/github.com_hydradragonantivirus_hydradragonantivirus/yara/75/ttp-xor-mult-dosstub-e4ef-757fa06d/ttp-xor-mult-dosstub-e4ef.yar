rule TTP_XOR_MULT_DOSStub_e4ef {
  strings:
    $key_e4ef = { b0 87 [2] c4 9f [2] 83 9d [2] c4 8c [2] 8a 80 [2] 86 8a [2] 91 81 [2] 8a cf [2] b7 }

  condition:
    any of them
}