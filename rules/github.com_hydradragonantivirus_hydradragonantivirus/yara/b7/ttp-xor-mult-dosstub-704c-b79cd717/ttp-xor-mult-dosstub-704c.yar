rule TTP_XOR_MULT_DOSStub_704c {
  strings:
    $key_704c = { 24 24 [2] 50 3c [2] 17 3e [2] 50 2f [2] 1e 23 [2] 12 29 [2] 05 22 [2] 1e 6c [2] 23 }

  condition:
    any of them
}