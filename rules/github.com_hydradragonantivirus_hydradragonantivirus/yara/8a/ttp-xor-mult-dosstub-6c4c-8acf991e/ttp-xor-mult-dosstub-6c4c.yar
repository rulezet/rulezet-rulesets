rule TTP_XOR_MULT_DOSStub_6c4c {
  strings:
    $key_6c4c = { 38 24 [2] 4c 3c [2] 0b 3e [2] 4c 2f [2] 02 23 [2] 0e 29 [2] 19 22 [2] 02 6c [2] 3f }

  condition:
    any of them
}