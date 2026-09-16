rule TTP_XOR_QUAD_CurrentVersionRun_0bdd {
  strings:
    $key_0bdd = { 58 b2 [2] 7c bc [2] 57 90 [2] 79 b2 [2] 6d a9 [2] 62 b3 [2] 7c ae [2] 7e af [2] 65 a9 [2] 79 ae [2] 65 81 }

  condition:
    any of them
}