rule TTP_XOR_MULT_DOSStub_1cac {
  strings:
    $key_1cac = { 48 c4 [2] 3c dc [2] 7b de [2] 3c cf [2] 72 c3 [2] 7e c9 [2] 69 c2 [2] 72 8c [2] 4f }

  condition:
    any of them
}