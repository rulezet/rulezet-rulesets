rule TTP_XOR_MULT_DOSStub_edd1 {
  strings:
    $key_edd1 = { b9 b9 [2] cd a1 [2] 8a a3 [2] cd b2 [2] 83 be [2] 8f b4 [2] 98 bf [2] 83 f1 [2] be }

  condition:
    any of them
}