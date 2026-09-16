rule TTP_XOR_MULT_DOSStub_65bc {
  strings:
    $key_65bc = { 31 d4 [2] 45 cc [2] 02 ce [2] 45 df [2] 0b d3 [2] 07 d9 [2] 10 d2 [2] 0b 9c [2] 36 }

  condition:
    any of them
}