rule TTP_XOR_QUAD_CurrentVersionRun_436a {
  strings:
    $key_436a = { 10 05 [2] 34 0b [2] 1f 27 [2] 31 05 [2] 25 1e [2] 2a 04 [2] 34 19 [2] 36 18 [2] 2d 1e [2] 31 19 [2] 2d 36 }

  condition:
    any of them
}