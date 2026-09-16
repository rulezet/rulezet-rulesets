rule TTP_XOR_QUAD_CurrentVersionRun_5421 {
  strings:
    $key_5421 = { 07 4e [2] 23 40 [2] 08 6c [2] 26 4e [2] 32 55 [2] 3d 4f [2] 23 52 [2] 21 53 [2] 3a 55 [2] 26 52 [2] 3a 7d }

  condition:
    any of them
}