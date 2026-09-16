rule TTP_XOR_MULT_DOSStub_411c {
  strings:
    $key_411c = { 15 74 [2] 61 6c [2] 26 6e [2] 61 7f [2] 2f 73 [2] 23 79 [2] 34 72 [2] 2f 3c [2] 12 }

  condition:
    any of them
}