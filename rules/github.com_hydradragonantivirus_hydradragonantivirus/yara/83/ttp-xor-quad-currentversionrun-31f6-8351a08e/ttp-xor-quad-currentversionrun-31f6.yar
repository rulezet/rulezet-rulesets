rule TTP_XOR_QUAD_CurrentVersionRun_31f6 {
  strings:
    $key_31f6 = { 62 99 [2] 46 97 [2] 6d bb [2] 43 99 [2] 57 82 [2] 58 98 [2] 46 85 [2] 44 84 [2] 5f 82 [2] 43 85 [2] 5f aa }

  condition:
    any of them
}