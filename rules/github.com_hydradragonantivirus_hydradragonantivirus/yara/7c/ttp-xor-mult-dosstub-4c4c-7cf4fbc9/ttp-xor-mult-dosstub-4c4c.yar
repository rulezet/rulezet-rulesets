rule TTP_XOR_MULT_DOSStub_4c4c {
  strings:
    $key_4c4c = { 18 24 [2] 6c 3c [2] 2b 3e [2] 6c 2f [2] 22 23 [2] 2e 29 [2] 39 22 [2] 22 6c [2] 1f }

  condition:
    any of them
}