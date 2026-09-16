rule TTP_XOR_QUAD_CurrentVersionRun_e739 {
  strings:
    $key_e739 = { b4 56 [2] 90 58 [2] bb 74 [2] 95 56 [2] 81 4d [2] 8e 57 [2] 90 4a [2] 92 4b [2] 89 4d [2] 95 4a [2] 89 65 }

  condition:
    any of them
}