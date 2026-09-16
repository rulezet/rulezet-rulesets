rule TTP_XOR_MULT_DOSStub_042c {
  strings:
    $key_042c = { 50 44 [2] 24 5c [2] 63 5e [2] 24 4f [2] 6a 43 [2] 66 49 [2] 71 42 [2] 6a 0c [2] 57 }

  condition:
    any of them
}