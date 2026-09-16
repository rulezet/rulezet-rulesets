rule TTP_XOR_QUAD_CurrentVersionRun_3401 {
  strings:
    $key_3401 = { 67 6e [2] 43 60 [2] 68 4c [2] 46 6e [2] 52 75 [2] 5d 6f [2] 43 72 [2] 41 73 [2] 5a 75 [2] 46 72 [2] 5a 5d }

  condition:
    any of them
}