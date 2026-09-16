rule TTP_XOR_QUAD_CurrentVersionRun_254c {
  strings:
    $key_254c = { 76 23 [2] 52 2d [2] 79 01 [2] 57 23 [2] 43 38 [2] 4c 22 [2] 52 3f [2] 50 3e [2] 4b 38 [2] 57 3f [2] 4b 10 }

  condition:
    any of them
}