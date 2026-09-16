rule TTP_XOR_QUAD_CurrentVersionRun_36f6 {
  strings:
    $key_36f6 = { 65 99 [2] 41 97 [2] 6a bb [2] 44 99 [2] 50 82 [2] 5f 98 [2] 41 85 [2] 43 84 [2] 58 82 [2] 44 85 [2] 58 aa }

  condition:
    any of them
}