rule TTP_XOR_MULT_DOSStub_1bad {
  strings:
    $key_1bad = { 4f c5 [2] 3b dd [2] 7c df [2] 3b ce [2] 75 c2 [2] 79 c8 [2] 6e c3 [2] 75 8d [2] 48 }

  condition:
    any of them
}