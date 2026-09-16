rule TTP_XOR_QUAD_CurrentVersionRun_430c {
  strings:
    $key_430c = { 10 63 [2] 34 6d [2] 1f 41 [2] 31 63 [2] 25 78 [2] 2a 62 [2] 34 7f [2] 36 7e [2] 2d 78 [2] 31 7f [2] 2d 50 }

  condition:
    any of them
}