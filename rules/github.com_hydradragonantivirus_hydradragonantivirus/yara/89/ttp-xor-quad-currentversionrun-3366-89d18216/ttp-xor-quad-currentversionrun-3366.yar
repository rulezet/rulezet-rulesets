rule TTP_XOR_QUAD_CurrentVersionRun_3366 {
  strings:
    $key_3366 = { 60 09 [2] 44 07 [2] 6f 2b [2] 41 09 [2] 55 12 [2] 5a 08 [2] 44 15 [2] 46 14 [2] 5d 12 [2] 41 15 [2] 5d 3a }

  condition:
    any of them
}