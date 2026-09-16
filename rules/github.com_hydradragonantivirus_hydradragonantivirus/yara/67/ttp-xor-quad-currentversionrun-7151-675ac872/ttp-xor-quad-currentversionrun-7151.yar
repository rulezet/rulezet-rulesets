rule TTP_XOR_QUAD_CurrentVersionRun_7151 {
  strings:
    $key_7151 = { 22 3e [2] 06 30 [2] 2d 1c [2] 03 3e [2] 17 25 [2] 18 3f [2] 06 22 [2] 04 23 [2] 1f 25 [2] 03 22 [2] 1f 0d }

  condition:
    any of them
}