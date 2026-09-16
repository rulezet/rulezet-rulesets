rule TTP_XOR_MULT_DOSStub_301c {
  strings:
    $key_301c = { 64 74 [2] 10 6c [2] 57 6e [2] 10 7f [2] 5e 73 [2] 52 79 [2] 45 72 [2] 5e 3c [2] 63 }

  condition:
    any of them
}