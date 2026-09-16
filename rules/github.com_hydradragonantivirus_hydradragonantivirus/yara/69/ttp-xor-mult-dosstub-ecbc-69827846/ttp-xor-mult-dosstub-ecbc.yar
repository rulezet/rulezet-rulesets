rule TTP_XOR_MULT_DOSStub_ecbc {
  strings:
    $key_ecbc = { b8 d4 [2] cc cc [2] 8b ce [2] cc df [2] 82 d3 [2] 8e d9 [2] 99 d2 [2] 82 9c [2] bf }

  condition:
    any of them
}