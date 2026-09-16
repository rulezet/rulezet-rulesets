rule TTP_XOR_MULT_DOSStub_7bad {
  strings:
    $key_7bad = { 2f c5 [2] 5b dd [2] 1c df [2] 5b ce [2] 15 c2 [2] 19 c8 [2] 0e c3 [2] 15 8d [2] 28 }

  condition:
    any of them
}