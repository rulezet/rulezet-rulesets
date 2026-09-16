rule TTP_XOR_QUAD_CurrentVersionRun_032b {
  strings:
    $key_032b = { 50 44 [2] 74 4a [2] 5f 66 [2] 71 44 [2] 65 5f [2] 6a 45 [2] 74 58 [2] 76 59 [2] 6d 5f [2] 71 58 [2] 6d 77 }

  condition:
    any of them
}