rule TTP_XOR_QUAD_CurrentVersionRun_11f6 {
  strings:
    $key_11f6 = { 42 99 [2] 66 97 [2] 4d bb [2] 63 99 [2] 77 82 [2] 78 98 [2] 66 85 [2] 64 84 [2] 7f 82 [2] 63 85 [2] 7f aa }

  condition:
    any of them
}