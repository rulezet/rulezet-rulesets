rule TTP_XOR_QUAD_CurrentVersionRun_4dec {
  strings:
    $key_4dec = { 1e 83 [2] 3a 8d [2] 11 a1 [2] 3f 83 [2] 2b 98 [2] 24 82 [2] 3a 9f [2] 38 9e [2] 23 98 [2] 3f 9f [2] 23 b0 }

  condition:
    any of them
}