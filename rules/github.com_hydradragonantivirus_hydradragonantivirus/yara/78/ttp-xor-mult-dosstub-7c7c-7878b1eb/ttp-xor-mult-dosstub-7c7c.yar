rule TTP_XOR_MULT_DOSStub_7c7c {
  strings:
    $key_7c7c = { 28 14 [2] 5c 0c [2] 1b 0e [2] 5c 1f [2] 12 13 [2] 1e 19 [2] 09 12 [2] 12 5c [2] 2f }

  condition:
    any of them
}