rule TTP_XOR_MULT_DOSStub_7a1c {
  strings:
    $key_7a1c = { 2e 74 [2] 5a 6c [2] 1d 6e [2] 5a 7f [2] 14 73 [2] 18 79 [2] 0f 72 [2] 14 3c [2] 29 }

  condition:
    any of them
}