rule TTP_XOR_MULT_DOSStub_354c {
  strings:
    $key_354c = { 61 24 [2] 15 3c [2] 52 3e [2] 15 2f [2] 5b 23 [2] 57 29 [2] 40 22 [2] 5b 6c [2] 66 }

  condition:
    any of them
}