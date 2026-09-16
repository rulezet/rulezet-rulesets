rule TTP_XOR_QUAD_CurrentVersionRun_e766 {
  strings:
    $key_e766 = { b4 09 [2] 90 07 [2] bb 2b [2] 95 09 [2] 81 12 [2] 8e 08 [2] 90 15 [2] 92 14 [2] 89 12 [2] 95 15 [2] 89 3a }

  condition:
    any of them
}