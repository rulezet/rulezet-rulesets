rule TTP_XOR_MULT_DOSStub_2bad {
  strings:
    $key_2bad = { 7f c5 [2] 0b dd [2] 4c df [2] 0b ce [2] 45 c2 [2] 49 c8 [2] 5e c3 [2] 45 8d [2] 78 }

  condition:
    any of them
}