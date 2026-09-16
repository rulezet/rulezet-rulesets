rule TTP_XOR_QUAD_CurrentVersionRun_3151 {
  strings:
    $key_3151 = { 62 3e [2] 46 30 [2] 6d 1c [2] 43 3e [2] 57 25 [2] 58 3f [2] 46 22 [2] 44 23 [2] 5f 25 [2] 43 22 [2] 5f 0d }

  condition:
    any of them
}