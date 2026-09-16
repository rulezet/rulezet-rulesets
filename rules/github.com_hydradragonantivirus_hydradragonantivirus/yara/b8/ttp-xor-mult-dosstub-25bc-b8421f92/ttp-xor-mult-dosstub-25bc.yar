rule TTP_XOR_MULT_DOSStub_25bc {
  strings:
    $key_25bc = { 71 d4 [2] 05 cc [2] 42 ce [2] 05 df [2] 4b d3 [2] 47 d9 [2] 50 d2 [2] 4b 9c [2] 76 }

  condition:
    any of them
}