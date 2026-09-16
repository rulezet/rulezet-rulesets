rule TTP_XOR_MULT_DOSStub_edd4 {
  strings:
    $key_edd4 = { b9 bc [2] cd a4 [2] 8a a6 [2] cd b7 [2] 83 bb [2] 8f b1 [2] 98 ba [2] 83 f4 [2] be }

  condition:
    any of them
}