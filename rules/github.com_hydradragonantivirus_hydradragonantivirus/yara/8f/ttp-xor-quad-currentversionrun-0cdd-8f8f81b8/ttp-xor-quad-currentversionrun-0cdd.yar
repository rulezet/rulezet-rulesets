rule TTP_XOR_QUAD_CurrentVersionRun_0cdd {
  strings:
    $key_0cdd = { 5f b2 [2] 7b bc [2] 50 90 [2] 7e b2 [2] 6a a9 [2] 65 b3 [2] 7b ae [2] 79 af [2] 62 a9 [2] 7e ae [2] 62 81 }

  condition:
    any of them
}