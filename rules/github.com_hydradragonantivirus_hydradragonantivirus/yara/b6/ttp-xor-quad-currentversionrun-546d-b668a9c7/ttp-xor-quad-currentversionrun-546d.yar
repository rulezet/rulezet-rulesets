rule TTP_XOR_QUAD_CurrentVersionRun_546d {
  strings:
    $key_546d = { 07 02 [2] 23 0c [2] 08 20 [2] 26 02 [2] 32 19 [2] 3d 03 [2] 23 1e [2] 21 1f [2] 3a 19 [2] 26 1e [2] 3a 31 }

  condition:
    any of them
}