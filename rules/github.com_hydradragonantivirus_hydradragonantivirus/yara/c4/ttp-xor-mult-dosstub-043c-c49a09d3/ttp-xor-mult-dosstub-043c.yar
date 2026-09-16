rule TTP_XOR_MULT_DOSStub_043c {
  strings:
    $key_043c = { 50 54 [2] 24 4c [2] 63 4e [2] 24 5f [2] 6a 53 [2] 66 59 [2] 71 52 [2] 6a 1c [2] 57 }

  condition:
    any of them
}