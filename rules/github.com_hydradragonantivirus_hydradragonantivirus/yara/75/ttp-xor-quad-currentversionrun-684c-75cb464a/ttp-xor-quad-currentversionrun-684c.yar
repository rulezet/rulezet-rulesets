rule TTP_XOR_QUAD_CurrentVersionRun_684c {
  strings:
    $key_684c = { 3b 23 [2] 1f 2d [2] 34 01 [2] 1a 23 [2] 0e 38 [2] 01 22 [2] 1f 3f [2] 1d 3e [2] 06 38 [2] 1a 3f [2] 06 10 }

  condition:
    any of them
}