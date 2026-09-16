rule TTP_XOR_MULT_DOSStub_141c {
  strings:
    $key_141c = { 40 74 [2] 34 6c [2] 73 6e [2] 34 7f [2] 7a 73 [2] 76 79 [2] 61 72 [2] 7a 3c [2] 47 }

  condition:
    any of them
}