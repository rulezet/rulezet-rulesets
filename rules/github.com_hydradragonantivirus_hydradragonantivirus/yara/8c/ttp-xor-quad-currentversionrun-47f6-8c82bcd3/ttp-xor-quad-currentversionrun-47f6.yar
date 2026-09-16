rule TTP_XOR_QUAD_CurrentVersionRun_47f6 {
  strings:
    $key_47f6 = { 14 99 [2] 30 97 [2] 1b bb [2] 35 99 [2] 21 82 [2] 2e 98 [2] 30 85 [2] 32 84 [2] 29 82 [2] 35 85 [2] 29 aa }

  condition:
    any of them
}