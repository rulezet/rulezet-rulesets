rule TTP_XOR_QUAD_CurrentVersionRun_01ea {
  strings:
    $key_01ea = { 52 85 [2] 76 8b [2] 5d a7 [2] 73 85 [2] 67 9e [2] 68 84 [2] 76 99 [2] 74 98 [2] 6f 9e [2] 73 99 [2] 6f b6 }

  condition:
    any of them
}