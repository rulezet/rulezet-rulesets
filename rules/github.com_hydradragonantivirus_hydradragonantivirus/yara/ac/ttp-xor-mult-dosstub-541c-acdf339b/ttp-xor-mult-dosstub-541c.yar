rule TTP_XOR_MULT_DOSStub_541c {
  strings:
    $key_541c = { 00 74 [2] 74 6c [2] 33 6e [2] 74 7f [2] 3a 73 [2] 36 79 [2] 21 72 [2] 3a 3c [2] 07 }

  condition:
    any of them
}