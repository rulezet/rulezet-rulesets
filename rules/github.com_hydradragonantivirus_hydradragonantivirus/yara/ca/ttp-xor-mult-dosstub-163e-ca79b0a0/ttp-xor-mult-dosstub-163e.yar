rule TTP_XOR_MULT_DOSStub_163e {
  strings:
    $key_163e = { 42 56 [2] 36 4e [2] 71 4c [2] 36 5d [2] 78 51 [2] 74 5b [2] 63 50 [2] 78 1e [2] 45 }

  condition:
    any of them
}