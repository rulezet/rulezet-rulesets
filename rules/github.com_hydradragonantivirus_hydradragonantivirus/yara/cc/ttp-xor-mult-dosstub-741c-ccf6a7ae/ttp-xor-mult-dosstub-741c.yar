rule TTP_XOR_MULT_DOSStub_741c {
  strings:
    $key_741c = { 20 74 [2] 54 6c [2] 13 6e [2] 54 7f [2] 1a 73 [2] 16 79 [2] 01 72 [2] 1a 3c [2] 27 }

  condition:
    any of them
}