rule TTP_XOR_MULT_DOSStub_7a4c {
  strings:
    $key_7a4c = { 2e 24 [2] 5a 3c [2] 1d 3e [2] 5a 2f [2] 14 23 [2] 18 29 [2] 0f 22 [2] 14 6c [2] 29 }

  condition:
    any of them
}