rule TTP_XOR_MULT_DOSStub_311c {
  strings:
    $key_311c = { 65 74 [2] 11 6c [2] 56 6e [2] 11 7f [2] 5f 73 [2] 53 79 [2] 44 72 [2] 5f 3c [2] 62 }

  condition:
    any of them
}