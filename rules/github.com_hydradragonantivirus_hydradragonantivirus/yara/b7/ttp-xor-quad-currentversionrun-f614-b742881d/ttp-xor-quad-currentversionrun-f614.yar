rule TTP_XOR_QUAD_CurrentVersionRun_f614 {
  strings:
    $key_f614 = { a5 7b [2] 81 75 [2] aa 59 [2] 84 7b [2] 90 60 [2] 9f 7a [2] 81 67 [2] 83 66 [2] 98 60 [2] 84 67 [2] 98 48 }

  condition:
    any of them
}