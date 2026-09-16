rule TTP_XOR_QUAD_CurrentVersionRun_f9dd {
  strings:
    $key_f9dd = { aa b2 [2] 8e bc [2] a5 90 [2] 8b b2 [2] 9f a9 [2] 90 b3 [2] 8e ae [2] 8c af [2] 97 a9 [2] 8b ae [2] 97 81 }

  condition:
    any of them
}