rule TTP_XOR_QUAD_CurrentVersionRun_4ddd {
  strings:
    $key_4ddd = { 1e b2 [2] 3a bc [2] 11 90 [2] 3f b2 [2] 2b a9 [2] 24 b3 [2] 3a ae [2] 38 af [2] 23 a9 [2] 3f ae [2] 23 81 }

  condition:
    any of them
}