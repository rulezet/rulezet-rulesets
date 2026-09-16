rule TTP_XOR_QUAD_CurrentVersionRun_01f6 {
  strings:
    $key_01f6 = { 52 99 [2] 76 97 [2] 5d bb [2] 73 99 [2] 67 82 [2] 68 98 [2] 76 85 [2] 74 84 [2] 6f 82 [2] 73 85 [2] 6f aa }

  condition:
    any of them
}