rule TTP_XOR_MULT_DOSStub_59bd {
  strings:
    $key_59bd = { 0d d5 [2] 79 cd [2] 3e cf [2] 79 de [2] 37 d2 [2] 3b d8 [2] 2c d3 [2] 37 9d [2] 0a }

  condition:
    any of them
}