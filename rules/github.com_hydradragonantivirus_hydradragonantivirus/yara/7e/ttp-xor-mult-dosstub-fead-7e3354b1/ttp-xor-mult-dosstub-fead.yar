rule TTP_XOR_MULT_DOSStub_fead {
  strings:
    $key_fead = { aa c5 [2] de dd [2] 99 df [2] de ce [2] 90 c2 [2] 9c c8 [2] 8b c3 [2] 90 8d [2] ad }

  condition:
    any of them
}