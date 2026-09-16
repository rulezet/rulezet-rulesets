rule TTP_XOR_MULT_DOSStub_c9bd {
  strings:
    $key_c9bd = { 9d d5 [2] e9 cd [2] ae cf [2] e9 de [2] a7 d2 [2] ab d8 [2] bc d3 [2] a7 9d [2] 9a }

  condition:
    any of them
}