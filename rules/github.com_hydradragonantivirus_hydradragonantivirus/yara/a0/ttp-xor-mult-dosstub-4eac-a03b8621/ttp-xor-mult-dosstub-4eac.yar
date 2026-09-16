rule TTP_XOR_MULT_DOSStub_4eac {
  strings:
    $key_4eac = { 1a c4 [2] 6e dc [2] 29 de [2] 6e cf [2] 20 c3 [2] 2c c9 [2] 3b c2 [2] 20 8c [2] 1d }

  condition:
    any of them
}