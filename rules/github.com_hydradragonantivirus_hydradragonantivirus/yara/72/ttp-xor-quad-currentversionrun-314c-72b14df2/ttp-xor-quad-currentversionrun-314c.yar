rule TTP_XOR_QUAD_CurrentVersionRun_314c {
  strings:
    $key_314c = { 62 23 [2] 46 2d [2] 6d 01 [2] 43 23 [2] 57 38 [2] 58 22 [2] 46 3f [2] 44 3e [2] 5f 38 [2] 43 3f [2] 5f 10 }

  condition:
    any of them
}