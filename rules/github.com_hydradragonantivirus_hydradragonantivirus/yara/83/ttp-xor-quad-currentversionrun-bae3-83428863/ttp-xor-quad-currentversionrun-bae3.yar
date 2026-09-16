rule TTP_XOR_QUAD_CurrentVersionRun_bae3 {
  strings:
    $key_bae3 = { e9 8c [2] cd 82 [2] e6 ae [2] c8 8c [2] dc 97 [2] d3 8d [2] cd 90 [2] cf 91 [2] d4 97 [2] c8 90 [2] d4 bf }

  condition:
    any of them
}