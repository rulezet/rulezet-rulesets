rule TTP_XOR_QUAD_CurrentVersionRun_3bdd {
  strings:
    $key_3bdd = { 68 b2 [2] 4c bc [2] 67 90 [2] 49 b2 [2] 5d a9 [2] 52 b3 [2] 4c ae [2] 4e af [2] 55 a9 [2] 49 ae [2] 55 81 }

  condition:
    any of them
}