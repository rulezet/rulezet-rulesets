rule TTP_XOR_MULT_DOSStub_eddf {
  strings:
    $key_eddf = { b9 b7 [2] cd af [2] 8a ad [2] cd bc [2] 83 b0 [2] 8f ba [2] 98 b1 [2] 83 ff [2] be }

  condition:
    any of them
}