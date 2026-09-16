rule TTP_XOR_MULT_DOSStub_f4ef {
  strings:
    $key_f4ef = { a0 87 [2] d4 9f [2] 93 9d [2] d4 8c [2] 9a 80 [2] 96 8a [2] 81 81 [2] 9a cf [2] a7 }

  condition:
    any of them
}