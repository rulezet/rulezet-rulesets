rule TTP_XOR_MULT_DOSStub_2cac {
  strings:
    $key_2cac = { 78 c4 [2] 0c dc [2] 4b de [2] 0c cf [2] 42 c3 [2] 4e c9 [2] 59 c2 [2] 42 8c [2] 7f }

  condition:
    any of them
}