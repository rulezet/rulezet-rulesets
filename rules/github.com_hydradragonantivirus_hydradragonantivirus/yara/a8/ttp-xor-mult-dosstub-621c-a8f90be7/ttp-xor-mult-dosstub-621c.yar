rule TTP_XOR_MULT_DOSStub_621c {
  strings:
    $key_621c = { 36 74 [2] 42 6c [2] 05 6e [2] 42 7f [2] 0c 73 [2] 00 79 [2] 17 72 [2] 0c 3c [2] 31 }

  condition:
    any of them
}