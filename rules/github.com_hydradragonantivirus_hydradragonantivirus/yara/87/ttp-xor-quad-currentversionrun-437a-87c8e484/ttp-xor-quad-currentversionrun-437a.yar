rule TTP_XOR_QUAD_CurrentVersionRun_437a {
  strings:
    $key_437a = { 10 15 [2] 34 1b [2] 1f 37 [2] 31 15 [2] 25 0e [2] 2a 14 [2] 34 09 [2] 36 08 [2] 2d 0e [2] 31 09 [2] 2d 26 }

  condition:
    any of them
}