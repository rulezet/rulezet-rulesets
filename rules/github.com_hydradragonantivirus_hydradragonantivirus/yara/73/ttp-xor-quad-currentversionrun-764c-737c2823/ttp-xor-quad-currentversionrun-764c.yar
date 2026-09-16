rule TTP_XOR_QUAD_CurrentVersionRun_764c {
  strings:
    $key_764c = { 25 23 [2] 01 2d [2] 2a 01 [2] 04 23 [2] 10 38 [2] 1f 22 [2] 01 3f [2] 03 3e [2] 18 38 [2] 04 3f [2] 18 10 }

  condition:
    any of them
}