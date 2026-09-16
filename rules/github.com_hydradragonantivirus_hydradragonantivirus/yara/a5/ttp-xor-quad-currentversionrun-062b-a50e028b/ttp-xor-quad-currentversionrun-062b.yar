rule TTP_XOR_QUAD_CurrentVersionRun_062b {
  strings:
    $key_062b = { 55 44 [2] 71 4a [2] 5a 66 [2] 74 44 [2] 60 5f [2] 6f 45 [2] 71 58 [2] 73 59 [2] 68 5f [2] 74 58 [2] 68 77 }

  condition:
    any of them
}