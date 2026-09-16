rule TTP_XOR_QUAD_CurrentVersionRun_eace {
  strings:
    $key_eace = { b9 a1 [2] 9d af [2] b6 83 [2] 98 a1 [2] 8c ba [2] 83 a0 [2] 9d bd [2] 9f bc [2] 84 ba [2] 98 bd [2] 84 92 }

  condition:
    any of them
}