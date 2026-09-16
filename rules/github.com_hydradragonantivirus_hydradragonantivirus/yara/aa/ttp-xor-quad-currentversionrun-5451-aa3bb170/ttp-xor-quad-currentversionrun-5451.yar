rule TTP_XOR_QUAD_CurrentVersionRun_5451 {
  strings:
    $key_5451 = { 07 3e [2] 23 30 [2] 08 1c [2] 26 3e [2] 32 25 [2] 3d 3f [2] 23 22 [2] 21 23 [2] 3a 25 [2] 26 22 [2] 3a 0d }

  condition:
    any of them
}