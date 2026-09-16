rule TTP_XOR_QUAD_CurrentVersionRun_46f6 {
  strings:
    $key_46f6 = { 15 99 [2] 31 97 [2] 1a bb [2] 34 99 [2] 20 82 [2] 2f 98 [2] 31 85 [2] 33 84 [2] 28 82 [2] 34 85 [2] 28 aa }

  condition:
    any of them
}