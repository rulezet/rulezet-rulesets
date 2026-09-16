rule TTP_XOR_MULT_DOSStub_0bad {
  strings:
    $key_0bad = { 5f c5 [2] 2b dd [2] 6c df [2] 2b ce [2] 65 c2 [2] 69 c8 [2] 7e c3 [2] 65 8d [2] 58 }

  condition:
    any of them
}