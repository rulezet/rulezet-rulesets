rule TTP_XOR_MULT_DOSStub_2e7c {
  strings:
    $key_2e7c = { 7a 14 [2] 0e 0c [2] 49 0e [2] 0e 1f [2] 40 13 [2] 4c 19 [2] 5b 12 [2] 40 5c [2] 7d }

  condition:
    any of them
}