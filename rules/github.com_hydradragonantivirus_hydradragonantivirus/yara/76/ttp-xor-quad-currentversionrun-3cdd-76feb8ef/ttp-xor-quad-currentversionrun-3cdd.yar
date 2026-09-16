rule TTP_XOR_QUAD_CurrentVersionRun_3cdd {
  strings:
    $key_3cdd = { 6f b2 [2] 4b bc [2] 60 90 [2] 4e b2 [2] 5a a9 [2] 55 b3 [2] 4b ae [2] 49 af [2] 52 a9 [2] 4e ae [2] 52 81 }

  condition:
    any of them
}