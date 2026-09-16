rule TTP_XOR_QUAD_CurrentVersionRun_272b {
  strings:
    $key_272b = { 74 44 [2] 50 4a [2] 7b 66 [2] 55 44 [2] 41 5f [2] 4e 45 [2] 50 58 [2] 52 59 [2] 49 5f [2] 55 58 [2] 49 77 }

  condition:
    any of them
}