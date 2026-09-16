rule TTP_XOR_MULT_DOSStub_6cac {
  strings:
    $key_6cac = { 38 c4 [2] 4c dc [2] 0b de [2] 4c cf [2] 02 c3 [2] 0e c9 [2] 19 c2 [2] 02 8c [2] 3f }

  condition:
    any of them
}