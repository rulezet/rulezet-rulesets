rule TTP_XOR_MULT_DOSStub_3e4c {
  strings:
    $key_3e4c = { 6a 24 [2] 1e 3c [2] 59 3e [2] 1e 2f [2] 50 23 [2] 5c 29 [2] 4b 22 [2] 50 6c [2] 6d }

  condition:
    any of them
}