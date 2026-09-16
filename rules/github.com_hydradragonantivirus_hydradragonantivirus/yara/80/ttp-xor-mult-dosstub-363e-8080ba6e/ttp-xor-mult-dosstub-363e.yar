rule TTP_XOR_MULT_DOSStub_363e {
  strings:
    $key_363e = { 62 56 [2] 16 4e [2] 51 4c [2] 16 5d [2] 58 51 [2] 54 5b [2] 43 50 [2] 58 1e [2] 65 }

  condition:
    any of them
}