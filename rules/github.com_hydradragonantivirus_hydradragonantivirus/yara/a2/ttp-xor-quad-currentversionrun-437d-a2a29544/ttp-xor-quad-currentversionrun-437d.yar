rule TTP_XOR_QUAD_CurrentVersionRun_437d {
  strings:
    $key_437d = { 10 12 [2] 34 1c [2] 1f 30 [2] 31 12 [2] 25 09 [2] 2a 13 [2] 34 0e [2] 36 0f [2] 2d 09 [2] 31 0e [2] 2d 21 }

  condition:
    any of them
}