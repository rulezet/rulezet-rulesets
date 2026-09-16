rule TTP_XOR_QUAD_CurrentVersionRun_5420 {
  strings:
    $key_5420 = { 07 4f [2] 23 41 [2] 08 6d [2] 26 4f [2] 32 54 [2] 3d 4e [2] 23 53 [2] 21 52 [2] 3a 54 [2] 26 53 [2] 3a 7c }

  condition:
    any of them
}