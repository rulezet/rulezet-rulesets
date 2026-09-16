rule TTP_XOR_QUAD_CurrentVersionRun_e7f6 {
  strings:
    $key_e7f6 = { b4 99 [2] 90 97 [2] bb bb [2] 95 99 [2] 81 82 [2] 8e 98 [2] 90 85 [2] 92 84 [2] 89 82 [2] 95 85 [2] 89 aa }

  condition:
    any of them
}