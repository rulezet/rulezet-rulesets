rule TTP_XOR_MULT_DOSStub_461c {
  strings:
    $key_461c = { 12 74 [2] 66 6c [2] 21 6e [2] 66 7f [2] 28 73 [2] 24 79 [2] 33 72 [2] 28 3c [2] 15 }

  condition:
    any of them
}