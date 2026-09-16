rule TTP_XOR_MULT_DOSStub_6eac {
  strings:
    $key_6eac = { 3a c4 [2] 4e dc [2] 09 de [2] 4e cf [2] 00 c3 [2] 0c c9 [2] 1b c2 [2] 00 8c [2] 3d }

  condition:
    any of them
}