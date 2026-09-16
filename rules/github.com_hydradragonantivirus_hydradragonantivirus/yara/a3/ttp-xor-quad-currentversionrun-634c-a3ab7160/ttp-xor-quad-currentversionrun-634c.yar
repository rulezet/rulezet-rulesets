rule TTP_XOR_QUAD_CurrentVersionRun_634c {
  strings:
    $key_634c = { 30 23 [2] 14 2d [2] 3f 01 [2] 11 23 [2] 05 38 [2] 0a 22 [2] 14 3f [2] 16 3e [2] 0d 38 [2] 11 3f [2] 0d 10 }

  condition:
    any of them
}