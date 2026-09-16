rule TTP_XOR_MULT_DOSStub_edd2 {
  strings:
    $key_edd2 = { b9 ba [2] cd a2 [2] 8a a0 [2] cd b1 [2] 83 bd [2] 8f b7 [2] 98 bc [2] 83 f2 [2] be }

  condition:
    any of them
}