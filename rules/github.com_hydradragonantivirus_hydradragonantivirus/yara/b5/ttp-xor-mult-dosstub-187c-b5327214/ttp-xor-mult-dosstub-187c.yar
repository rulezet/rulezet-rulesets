rule TTP_XOR_MULT_DOSStub_187c {
  strings:
    $key_187c = { 4c 14 [2] 38 0c [2] 7f 0e [2] 38 1f [2] 76 13 [2] 7a 19 [2] 6d 12 [2] 76 5c [2] 4b }

  condition:
    any of them
}