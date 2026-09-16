rule TTP_XOR_MULT_DOSStub_400e {
  strings:
    $key_400e = { 14 66 [2] 60 7e [2] 27 7c [2] 60 6d [2] 2e 61 [2] 22 6b [2] 35 60 [2] 2e 2e [2] 13 }

  condition:
    any of them
}