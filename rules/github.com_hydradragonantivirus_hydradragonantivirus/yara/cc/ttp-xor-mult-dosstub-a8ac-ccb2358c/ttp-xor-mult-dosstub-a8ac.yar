rule TTP_XOR_MULT_DOSStub_a8ac {
  strings:
    $key_a8ac = { fc c4 [2] 88 dc [2] cf de [2] 88 cf [2] c6 c3 [2] ca c9 [2] dd c2 [2] c6 8c [2] fb }

  condition:
    any of them
}