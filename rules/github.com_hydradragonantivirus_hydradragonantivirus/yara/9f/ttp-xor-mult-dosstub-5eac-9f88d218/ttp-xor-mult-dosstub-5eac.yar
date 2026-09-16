rule TTP_XOR_MULT_DOSStub_5eac {
  strings:
    $key_5eac = { 0a c4 [2] 7e dc [2] 39 de [2] 7e cf [2] 30 c3 [2] 3c c9 [2] 2b c2 [2] 30 8c [2] 0d }

  condition:
    any of them
}