rule TTP_XOR_MULT_DOSStub_70ee {
  strings:
    $key_70ee = { 24 86 [2] 50 9e [2] 17 9c [2] 50 8d [2] 1e 81 [2] 12 8b [2] 05 80 [2] 1e ce [2] 23 }

  condition:
    any of them
}