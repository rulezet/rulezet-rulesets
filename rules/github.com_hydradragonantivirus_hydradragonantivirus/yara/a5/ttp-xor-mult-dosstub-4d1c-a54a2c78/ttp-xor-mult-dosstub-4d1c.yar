rule TTP_XOR_MULT_DOSStub_4d1c {
  strings:
    $key_4d1c = { 19 74 [2] 6d 6c [2] 2a 6e [2] 6d 7f [2] 23 73 [2] 2f 79 [2] 38 72 [2] 23 3c [2] 1e }

  condition:
    any of them
}