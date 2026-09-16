rule TTP_XOR_MULT_DOSStub_4d4c {
  strings:
    $key_4d4c = { 19 24 [2] 6d 3c [2] 2a 3e [2] 6d 2f [2] 23 23 [2] 2f 29 [2] 38 22 [2] 23 6c [2] 1e }

  condition:
    any of them
}