rule TTP_XOR_QUAD_CurrentVersionRun_1ddd {
  strings:
    $key_1ddd = { 4e b2 [2] 6a bc [2] 41 90 [2] 6f b2 [2] 7b a9 [2] 74 b3 [2] 6a ae [2] 68 af [2] 73 a9 [2] 6f ae [2] 73 81 }

  condition:
    any of them
}