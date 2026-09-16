rule TTP_XOR_MULT_DOSStub_7d7c {
  strings:
    $key_7d7c = { 29 14 [2] 5d 0c [2] 1a 0e [2] 5d 1f [2] 13 13 [2] 1f 19 [2] 08 12 [2] 13 5c [2] 2e }

  condition:
    any of them
}