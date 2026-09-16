rule TTP_XOR_QUAD_CurrentVersionRun_f605 {
  strings:
    $key_f605 = { a5 6a [2] 81 64 [2] aa 48 [2] 84 6a [2] 90 71 [2] 9f 6b [2] 81 76 [2] 83 77 [2] 98 71 [2] 84 76 [2] 98 59 }

  condition:
    any of them
}