rule TTP_XOR_QUAD_CurrentVersionRun_437c {
  strings:
    $key_437c = { 10 13 [2] 34 1d [2] 1f 31 [2] 31 13 [2] 25 08 [2] 2a 12 [2] 34 0f [2] 36 0e [2] 2d 08 [2] 31 0f [2] 2d 20 }

  condition:
    any of them
}