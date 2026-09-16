rule TTP_XOR_QUAD_CurrentVersionRun_6bdd {
  strings:
    $key_6bdd = { 38 b2 [2] 1c bc [2] 37 90 [2] 19 b2 [2] 0d a9 [2] 02 b3 [2] 1c ae [2] 1e af [2] 05 a9 [2] 19 ae [2] 05 81 }

  condition:
    any of them
}