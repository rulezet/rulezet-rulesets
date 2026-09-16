rule TTP_XOR_MULT_DOSStub_5d7c {
  strings:
    $key_5d7c = { 09 14 [2] 7d 0c [2] 3a 0e [2] 7d 1f [2] 33 13 [2] 3f 19 [2] 28 12 [2] 33 5c [2] 0e }

  condition:
    any of them
}