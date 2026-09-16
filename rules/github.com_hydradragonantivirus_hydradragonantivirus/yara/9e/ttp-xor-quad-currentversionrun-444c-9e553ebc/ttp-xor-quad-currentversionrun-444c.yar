rule TTP_XOR_QUAD_CurrentVersionRun_444c {
  strings:
    $key_444c = { 17 23 [2] 33 2d [2] 18 01 [2] 36 23 [2] 22 38 [2] 2d 22 [2] 33 3f [2] 31 3e [2] 2a 38 [2] 36 3f [2] 2a 10 }

  condition:
    any of them
}