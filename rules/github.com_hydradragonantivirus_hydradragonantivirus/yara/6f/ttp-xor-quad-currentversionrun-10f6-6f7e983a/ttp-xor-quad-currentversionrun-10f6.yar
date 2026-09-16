rule TTP_XOR_QUAD_CurrentVersionRun_10f6 {
  strings:
    $key_10f6 = { 43 99 [2] 67 97 [2] 4c bb [2] 62 99 [2] 76 82 [2] 79 98 [2] 67 85 [2] 65 84 [2] 7e 82 [2] 62 85 [2] 7e aa }

  condition:
    any of them
}