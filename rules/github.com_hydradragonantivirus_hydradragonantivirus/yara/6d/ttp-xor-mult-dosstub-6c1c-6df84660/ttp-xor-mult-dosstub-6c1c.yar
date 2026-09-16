rule TTP_XOR_MULT_DOSStub_6c1c {
  strings:
    $key_6c1c = { 38 74 [2] 4c 6c [2] 0b 6e [2] 4c 7f [2] 02 73 [2] 0e 79 [2] 19 72 [2] 02 3c [2] 3f }

  condition:
    any of them
}