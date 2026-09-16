rule TTP_XOR_QUAD_CurrentVersionRun_f656 {
  strings:
    $key_f656 = { a5 39 [2] 81 37 [2] aa 1b [2] 84 39 [2] 90 22 [2] 9f 38 [2] 81 25 [2] 83 24 [2] 98 22 [2] 84 25 [2] 98 0a }

  condition:
    any of them
}