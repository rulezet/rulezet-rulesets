rule TTP_XOR_QUAD_CurrentVersionRun_2366 {
  strings:
    $key_2366 = { 70 09 [2] 54 07 [2] 7f 2b [2] 51 09 [2] 45 12 [2] 4a 08 [2] 54 15 [2] 56 14 [2] 4d 12 [2] 51 15 [2] 4d 3a }

  condition:
    any of them
}