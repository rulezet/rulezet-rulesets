rule TTP_XOR_QUAD_CurrentVersionRun_11ea {
  strings:
    $key_11ea = { 42 85 [2] 66 8b [2] 4d a7 [2] 63 85 [2] 77 9e [2] 78 84 [2] 66 99 [2] 64 98 [2] 7f 9e [2] 63 99 [2] 7f b6 }

  condition:
    any of them
}