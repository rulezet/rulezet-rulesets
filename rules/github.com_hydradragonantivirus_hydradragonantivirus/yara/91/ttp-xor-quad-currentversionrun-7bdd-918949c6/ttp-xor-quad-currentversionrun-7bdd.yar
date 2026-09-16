rule TTP_XOR_QUAD_CurrentVersionRun_7bdd {
  strings:
    $key_7bdd = { 28 b2 [2] 0c bc [2] 27 90 [2] 09 b2 [2] 1d a9 [2] 12 b3 [2] 0c ae [2] 0e af [2] 15 a9 [2] 09 ae [2] 15 81 }

  condition:
    any of them
}