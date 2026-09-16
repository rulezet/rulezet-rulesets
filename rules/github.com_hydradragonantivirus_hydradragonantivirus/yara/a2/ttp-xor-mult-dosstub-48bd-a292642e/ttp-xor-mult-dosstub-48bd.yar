rule TTP_XOR_MULT_DOSStub_48bd {
  strings:
    $key_48bd = { 1c d5 [2] 68 cd [2] 2f cf [2] 68 de [2] 26 d2 [2] 2a d8 [2] 3d d3 [2] 26 9d [2] 1b }

  condition:
    any of them
}