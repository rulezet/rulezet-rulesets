rule TTP_XOR_MULT_DOSStub_3eac {
  strings:
    $key_3eac = { 6a c4 [2] 1e dc [2] 59 de [2] 1e cf [2] 50 c3 [2] 5c c9 [2] 4b c2 [2] 50 8c [2] 6d }

  condition:
    any of them
}