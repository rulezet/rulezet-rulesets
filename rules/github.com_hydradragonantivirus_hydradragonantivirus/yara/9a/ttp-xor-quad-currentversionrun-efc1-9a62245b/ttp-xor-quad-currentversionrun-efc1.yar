rule TTP_XOR_QUAD_CurrentVersionRun_efc1 {
  strings:
    $key_efc1 = { bc ae [2] 98 a0 [2] b3 8c [2] 9d ae [2] 89 b5 [2] 86 af [2] 98 b2 [2] 9a b3 [2] 81 b5 [2] 9d b2 [2] 81 9d }

  condition:
    any of them
}