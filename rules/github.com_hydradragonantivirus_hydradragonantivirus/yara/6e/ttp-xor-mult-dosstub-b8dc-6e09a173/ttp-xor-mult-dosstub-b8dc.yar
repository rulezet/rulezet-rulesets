rule TTP_XOR_MULT_DOSStub_b8dc {
  strings:
    $key_b8dc = { ec b4 [2] 98 ac [2] df ae [2] 98 bf [2] d6 b3 [2] da b9 [2] cd b2 [2] d6 fc [2] eb }

  condition:
    any of them
}