rule TTP_XOR_MULT_DOSStub_61bc {
  strings:
    $key_61bc = { 35 d4 [2] 41 cc [2] 06 ce [2] 41 df [2] 0f d3 [2] 03 d9 [2] 14 d2 [2] 0f 9c [2] 32 }

  condition:
    any of them
}