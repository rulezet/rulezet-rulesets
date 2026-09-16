rule TTP_XOR_MULT_DOSStub_f3bf {
  strings:
    $key_f3bf = { a7 d7 [2] d3 cf [2] 94 cd [2] d3 dc [2] 9d d0 [2] 91 da [2] 86 d1 [2] 9d 9f [2] a0 }

  condition:
    any of them
}