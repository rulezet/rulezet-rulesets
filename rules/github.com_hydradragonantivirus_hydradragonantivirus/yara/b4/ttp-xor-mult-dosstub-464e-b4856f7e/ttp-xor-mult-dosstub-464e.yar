rule TTP_XOR_MULT_DOSStub_464e {
  strings:
    $key_464e = { 12 26 [2] 66 3e [2] 21 3c [2] 66 2d [2] 28 21 [2] 24 2b [2] 33 20 [2] 28 6e [2] 15 }

  condition:
    any of them
}