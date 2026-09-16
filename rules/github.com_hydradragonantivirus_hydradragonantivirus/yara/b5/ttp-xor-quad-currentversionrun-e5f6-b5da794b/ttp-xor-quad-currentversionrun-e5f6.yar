rule TTP_XOR_QUAD_CurrentVersionRun_e5f6 {
  strings:
    $key_e5f6 = { b6 99 [2] 92 97 [2] b9 bb [2] 97 99 [2] 83 82 [2] 8c 98 [2] 92 85 [2] 90 84 [2] 8b 82 [2] 97 85 [2] 8b aa }

  condition:
    any of them
}