rule TTP_XOR_MULT_DOSStub_57bc {
  strings:
    $key_57bc = { 03 d4 [2] 77 cc [2] 30 ce [2] 77 df [2] 39 d3 [2] 35 d9 [2] 22 d2 [2] 39 9c [2] 04 }

  condition:
    any of them
}