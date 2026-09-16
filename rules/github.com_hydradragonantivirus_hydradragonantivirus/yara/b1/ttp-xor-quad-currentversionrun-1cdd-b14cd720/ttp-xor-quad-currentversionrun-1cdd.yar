rule TTP_XOR_QUAD_CurrentVersionRun_1cdd {
  strings:
    $key_1cdd = { 4f b2 [2] 6b bc [2] 40 90 [2] 6e b2 [2] 7a a9 [2] 75 b3 [2] 6b ae [2] 69 af [2] 72 a9 [2] 6e ae [2] 72 81 }

  condition:
    any of them
}