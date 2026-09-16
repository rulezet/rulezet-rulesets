rule TTP_XOR_QUAD_CurrentVersionRun_eff6 {
  strings:
    $key_eff6 = { bc 99 [2] 98 97 [2] b3 bb [2] 9d 99 [2] 89 82 [2] 86 98 [2] 98 85 [2] 9a 84 [2] 81 82 [2] 9d 85 [2] 81 aa }

  condition:
    any of them
}