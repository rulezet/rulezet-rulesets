rule TTP_XOR_MULT_DOSStub_0cac {
  strings:
    $key_0cac = { 58 c4 [2] 2c dc [2] 6b de [2] 2c cf [2] 62 c3 [2] 6e c9 [2] 79 c2 [2] 62 8c [2] 5f }

  condition:
    any of them
}