rule TTP_XOR_QUAD_CurrentVersionRun_3625 {
  strings:
    $key_3625 = { 65 4a [2] 41 44 [2] 6a 68 [2] 44 4a [2] 50 51 [2] 5f 4b [2] 41 56 [2] 43 57 [2] 58 51 [2] 44 56 [2] 58 79 }

  condition:
    any of them
}