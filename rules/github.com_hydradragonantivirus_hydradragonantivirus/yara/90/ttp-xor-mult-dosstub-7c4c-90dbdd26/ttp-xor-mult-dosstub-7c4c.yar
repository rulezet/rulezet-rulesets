rule TTP_XOR_MULT_DOSStub_7c4c {
  strings:
    $key_7c4c = { 28 24 [2] 5c 3c [2] 1b 3e [2] 5c 2f [2] 12 23 [2] 1e 29 [2] 09 22 [2] 12 6c [2] 2f }

  condition:
    any of them
}