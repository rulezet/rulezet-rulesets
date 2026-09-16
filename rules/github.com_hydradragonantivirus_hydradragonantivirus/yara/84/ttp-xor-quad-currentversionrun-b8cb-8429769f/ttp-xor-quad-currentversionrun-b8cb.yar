rule TTP_XOR_QUAD_CurrentVersionRun_b8cb {
  strings:
    $key_b8cb = { eb a4 [2] cf aa [2] e4 86 [2] ca a4 [2] de bf [2] d1 a5 [2] cf b8 [2] cd b9 [2] d6 bf [2] ca b8 [2] d6 97 }

  condition:
    any of them
}