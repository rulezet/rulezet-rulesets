rule TTP_XOR_QUAD_CurrentVersionRun_5431 {
  strings:
    $key_5431 = { 07 5e [2] 23 50 [2] 08 7c [2] 26 5e [2] 32 45 [2] 3d 5f [2] 23 42 [2] 21 43 [2] 3a 45 [2] 26 42 [2] 3a 6d }

  condition:
    any of them
}