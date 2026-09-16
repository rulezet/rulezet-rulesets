rule TTP_XOR_QUAD_CurrentVersionRun_2cdd {
  strings:
    $key_2cdd = { 7f b2 [2] 5b bc [2] 70 90 [2] 5e b2 [2] 4a a9 [2] 45 b3 [2] 5b ae [2] 59 af [2] 42 a9 [2] 5e ae [2] 42 81 }

  condition:
    any of them
}