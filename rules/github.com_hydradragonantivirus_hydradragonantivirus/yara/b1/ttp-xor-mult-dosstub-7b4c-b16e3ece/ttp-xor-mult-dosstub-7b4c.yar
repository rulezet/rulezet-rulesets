rule TTP_XOR_MULT_DOSStub_7b4c {
  strings:
    $key_7b4c = { 2f 24 [2] 5b 3c [2] 1c 3e [2] 5b 2f [2] 15 23 [2] 19 29 [2] 0e 22 [2] 15 6c [2] 28 }

  condition:
    any of them
}