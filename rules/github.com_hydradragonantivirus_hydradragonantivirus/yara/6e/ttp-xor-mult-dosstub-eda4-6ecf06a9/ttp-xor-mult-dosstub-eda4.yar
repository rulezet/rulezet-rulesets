rule TTP_XOR_MULT_DOSStub_eda4 {
  strings:
    $key_eda4 = { b9 cc [2] cd d4 [2] 8a d6 [2] cd c7 [2] 83 cb [2] 8f c1 [2] 98 ca [2] 83 84 [2] be }

  condition:
    any of them
}