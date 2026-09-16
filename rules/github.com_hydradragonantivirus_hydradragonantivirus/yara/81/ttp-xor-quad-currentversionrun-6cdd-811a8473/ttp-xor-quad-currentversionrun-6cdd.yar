rule TTP_XOR_QUAD_CurrentVersionRun_6cdd {
  strings:
    $key_6cdd = { 3f b2 [2] 1b bc [2] 30 90 [2] 1e b2 [2] 0a a9 [2] 05 b3 [2] 1b ae [2] 19 af [2] 02 a9 [2] 1e ae [2] 02 81 }

  condition:
    any of them
}