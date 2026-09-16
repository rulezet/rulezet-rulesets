rule TTP_XOR_MULT_DOSStub_051c {
  strings:
    $key_051c = { 51 74 [2] 25 6c [2] 62 6e [2] 25 7f [2] 6b 73 [2] 67 79 [2] 70 72 [2] 6b 3c [2] 56 }

  condition:
    any of them
}