rule TTP_XOR_QUAD_CurrentVersionRun_142b {
  strings:
    $key_142b = { 47 44 [2] 63 4a [2] 48 66 [2] 66 44 [2] 72 5f [2] 7d 45 [2] 63 58 [2] 61 59 [2] 7a 5f [2] 66 58 [2] 7a 77 }

  condition:
    any of them
}