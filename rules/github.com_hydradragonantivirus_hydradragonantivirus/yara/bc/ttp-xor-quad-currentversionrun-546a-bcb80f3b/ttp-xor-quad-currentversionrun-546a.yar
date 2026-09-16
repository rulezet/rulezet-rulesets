rule TTP_XOR_QUAD_CurrentVersionRun_546a {
  strings:
    $key_546a = { 07 05 [2] 23 0b [2] 08 27 [2] 26 05 [2] 32 1e [2] 3d 04 [2] 23 19 [2] 21 18 [2] 3a 1e [2] 26 19 [2] 3a 36 }

  condition:
    any of them
}