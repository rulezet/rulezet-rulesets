rule TTP_XOR_QUAD_CurrentVersionRun_712a {
  strings:
    $key_712a = { 22 45 [2] 06 4b [2] 2d 67 [2] 03 45 [2] 17 5e [2] 18 44 [2] 06 59 [2] 04 58 [2] 1f 5e [2] 03 59 [2] 1f 76 }

  condition:
    any of them
}