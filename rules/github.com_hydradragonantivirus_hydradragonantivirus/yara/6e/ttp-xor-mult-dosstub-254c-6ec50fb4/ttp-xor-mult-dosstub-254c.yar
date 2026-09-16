rule TTP_XOR_MULT_DOSStub_254c {
  strings:
    $key_254c = { 71 24 [2] 05 3c [2] 42 3e [2] 05 2f [2] 4b 23 [2] 47 29 [2] 50 22 [2] 4b 6c [2] 76 }

  condition:
    any of them
}