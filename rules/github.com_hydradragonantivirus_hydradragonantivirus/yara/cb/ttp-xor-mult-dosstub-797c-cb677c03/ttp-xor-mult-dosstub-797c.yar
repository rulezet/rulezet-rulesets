rule TTP_XOR_MULT_DOSStub_797c {
  strings:
    $key_797c = { 2d 14 [2] 59 0c [2] 1e 0e [2] 59 1f [2] 17 13 [2] 1b 19 [2] 0c 12 [2] 17 5c [2] 2a }

  condition:
    any of them
}