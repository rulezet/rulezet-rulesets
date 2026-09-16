rule TTP_XOR_QUAD_CurrentVersionRun_5432 {
  strings:
    $key_5432 = { 07 5d [2] 23 53 [2] 08 7f [2] 26 5d [2] 32 46 [2] 3d 5c [2] 23 41 [2] 21 40 [2] 3a 46 [2] 26 41 [2] 3a 6e }

  condition:
    any of them
}