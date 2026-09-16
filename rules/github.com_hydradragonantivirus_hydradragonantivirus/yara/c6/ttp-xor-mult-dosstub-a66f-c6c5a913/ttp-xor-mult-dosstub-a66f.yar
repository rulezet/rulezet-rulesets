rule TTP_XOR_MULT_DOSStub_a66f {
  strings:
    $key_a66f = { f2 07 [2] 86 1f [2] c1 1d [2] 86 0c [2] c8 00 [2] c4 0a [2] d3 01 [2] c8 4f [2] f5 }

  condition:
    any of them
}