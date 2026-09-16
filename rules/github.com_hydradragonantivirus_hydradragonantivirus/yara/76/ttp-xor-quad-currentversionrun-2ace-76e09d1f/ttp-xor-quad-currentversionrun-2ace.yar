rule TTP_XOR_QUAD_CurrentVersionRun_2ace {
  strings:
    $key_2ace = { 79 a1 [2] 5d af [2] 76 83 [2] 58 a1 [2] 4c ba [2] 43 a0 [2] 5d bd [2] 5f bc [2] 44 ba [2] 58 bd [2] 44 92 }

  condition:
    any of them
}