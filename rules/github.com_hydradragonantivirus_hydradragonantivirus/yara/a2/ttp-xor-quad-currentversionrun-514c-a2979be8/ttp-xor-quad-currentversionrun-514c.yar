rule TTP_XOR_QUAD_CurrentVersionRun_514c {
  strings:
    $key_514c = { 02 23 [2] 26 2d [2] 0d 01 [2] 23 23 [2] 37 38 [2] 38 22 [2] 26 3f [2] 24 3e [2] 3f 38 [2] 23 3f [2] 3f 10 }

  condition:
    any of them
}