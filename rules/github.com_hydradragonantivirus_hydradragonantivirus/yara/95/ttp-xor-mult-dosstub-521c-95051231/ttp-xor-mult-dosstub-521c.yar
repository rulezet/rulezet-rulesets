rule TTP_XOR_MULT_DOSStub_521c {
  strings:
    $key_521c = { 06 74 [2] 72 6c [2] 35 6e [2] 72 7f [2] 3c 73 [2] 30 79 [2] 27 72 [2] 3c 3c [2] 01 }

  condition:
    any of them
}