rule TTP_XOR_MULT_DOSStub_394c {
  strings:
    $key_394c = { 6d 24 [2] 19 3c [2] 5e 3e [2] 19 2f [2] 57 23 [2] 5b 29 [2] 4c 22 [2] 57 6c [2] 6a }

  condition:
    any of them
}