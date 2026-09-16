rule TTP_XOR_MULT_DOSStub_561c {
  strings:
    $key_561c = { 02 74 [2] 76 6c [2] 31 6e [2] 76 7f [2] 38 73 [2] 34 79 [2] 23 72 [2] 38 3c [2] 05 }

  condition:
    any of them
}