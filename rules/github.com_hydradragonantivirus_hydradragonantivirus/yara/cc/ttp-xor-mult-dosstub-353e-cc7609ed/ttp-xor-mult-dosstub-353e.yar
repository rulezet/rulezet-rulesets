rule TTP_XOR_MULT_DOSStub_353e {
  strings:
    $key_353e = { 61 56 [2] 15 4e [2] 52 4c [2] 15 5d [2] 5b 51 [2] 57 5b [2] 40 50 [2] 5b 1e [2] 66 }

  condition:
    any of them
}