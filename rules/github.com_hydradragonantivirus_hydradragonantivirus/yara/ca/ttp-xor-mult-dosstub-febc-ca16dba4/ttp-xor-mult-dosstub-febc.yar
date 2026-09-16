rule TTP_XOR_MULT_DOSStub_febc {
  strings:
    $key_febc = { aa d4 [2] de cc [2] 99 ce [2] de df [2] 90 d3 [2] 9c d9 [2] 8b d2 [2] 90 9c [2] ad }

  condition:
    any of them
}