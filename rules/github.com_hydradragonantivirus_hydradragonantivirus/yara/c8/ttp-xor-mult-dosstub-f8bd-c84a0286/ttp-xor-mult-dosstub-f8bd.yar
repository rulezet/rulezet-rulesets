rule TTP_XOR_MULT_DOSStub_f8bd {
  strings:
    $key_f8bd = { ac d5 [2] d8 cd [2] 9f cf [2] d8 de [2] 96 d2 [2] 9a d8 [2] 8d d3 [2] 96 9d [2] ab }

  condition:
    any of them
}