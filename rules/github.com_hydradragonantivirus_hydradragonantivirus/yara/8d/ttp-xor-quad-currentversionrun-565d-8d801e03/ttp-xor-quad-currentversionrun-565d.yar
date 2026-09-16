rule TTP_XOR_QUAD_CurrentVersionRun_565d {
  strings:
    $key_565d = { 05 32 [2] 21 3c [2] 0a 10 [2] 24 32 [2] 30 29 [2] 3f 33 [2] 21 2e [2] 23 2f [2] 38 29 [2] 24 2e [2] 38 01 }

  condition:
    any of them
}