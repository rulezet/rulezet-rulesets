rule TTP_XOR_QUAD_CurrentVersionRun_e738 {
  strings:
    $key_e738 = { b4 57 [2] 90 59 [2] bb 75 [2] 95 57 [2] 81 4c [2] 8e 56 [2] 90 4b [2] 92 4a [2] 89 4c [2] 95 4b [2] 89 64 }

  condition:
    any of them
}