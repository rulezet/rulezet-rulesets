rule TTP_XOR_MULT_DOSStub_efbd {
  strings:
    $key_efbd = { bb d5 [2] cf cd [2] 88 cf [2] cf de [2] 81 d2 [2] 8d d8 [2] 9a d3 [2] 81 9d [2] bc }

  condition:
    any of them
}