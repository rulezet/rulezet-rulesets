rule TTP_XOR_MULT_DOSStub_641c {
  strings:
    $key_641c = { 30 74 [2] 44 6c [2] 03 6e [2] 44 7f [2] 0a 73 [2] 06 79 [2] 11 72 [2] 0a 3c [2] 37 }

  condition:
    any of them
}