rule TTP_XOR_QUAD_CurrentVersionRun_717a {
  strings:
    $key_717a = { 22 15 [2] 06 1b [2] 2d 37 [2] 03 15 [2] 17 0e [2] 18 14 [2] 06 09 [2] 04 08 [2] 1f 0e [2] 03 09 [2] 1f 26 }

  condition:
    any of them
}