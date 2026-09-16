rule TTP_XOR_MULT_DOSStub_703c {
  strings:
    $key_703c = { 24 54 [2] 50 4c [2] 17 4e [2] 50 5f [2] 1e 53 [2] 12 59 [2] 05 52 [2] 1e 1c [2] 23 }

  condition:
    any of them
}