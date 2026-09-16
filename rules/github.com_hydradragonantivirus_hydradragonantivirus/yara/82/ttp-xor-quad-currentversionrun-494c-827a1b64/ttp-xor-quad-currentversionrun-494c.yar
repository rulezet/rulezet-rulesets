rule TTP_XOR_QUAD_CurrentVersionRun_494c {
  strings:
    $key_494c = { 1a 23 [2] 3e 2d [2] 15 01 [2] 3b 23 [2] 2f 38 [2] 20 22 [2] 3e 3f [2] 3c 3e [2] 27 38 [2] 3b 3f [2] 27 10 }

  condition:
    any of them
}