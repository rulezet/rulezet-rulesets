rule TTP_XOR_QUAD_CurrentVersionRun_e2d1 {
  strings:
    $key_e2d1 = { b1 be [2] 95 b0 [2] be 9c [2] 90 be [2] 84 a5 [2] 8b bf [2] 95 a2 [2] 97 a3 [2] 8c a5 [2] 90 a2 [2] 8c 8d }

  condition:
    any of them
}