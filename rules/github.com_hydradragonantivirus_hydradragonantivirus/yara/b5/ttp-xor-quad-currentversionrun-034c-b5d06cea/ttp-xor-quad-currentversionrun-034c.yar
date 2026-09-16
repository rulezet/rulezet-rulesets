rule TTP_XOR_QUAD_CurrentVersionRun_034c {
  strings:
    $key_034c = { 50 23 [2] 74 2d [2] 5f 01 [2] 71 23 [2] 65 38 [2] 6a 22 [2] 74 3f [2] 76 3e [2] 6d 38 [2] 71 3f [2] 6d 10 }

  condition:
    any of them
}