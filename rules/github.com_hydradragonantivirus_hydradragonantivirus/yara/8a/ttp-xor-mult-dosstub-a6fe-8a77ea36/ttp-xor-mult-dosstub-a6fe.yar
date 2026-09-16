rule TTP_XOR_MULT_DOSStub_a6fe {
  strings:
    $key_a6fe = { f2 96 [2] 86 8e [2] c1 8c [2] 86 9d [2] c8 91 [2] c4 9b [2] d3 90 [2] c8 de [2] f5 }

  condition:
    any of them
}