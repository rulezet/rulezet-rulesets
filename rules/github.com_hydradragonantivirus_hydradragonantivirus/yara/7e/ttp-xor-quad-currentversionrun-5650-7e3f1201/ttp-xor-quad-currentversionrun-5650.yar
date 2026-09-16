rule TTP_XOR_QUAD_CurrentVersionRun_5650 {
  strings:
    $key_5650 = { 05 3f [2] 21 31 [2] 0a 1d [2] 24 3f [2] 30 24 [2] 3f 3e [2] 21 23 [2] 23 22 [2] 38 24 [2] 24 23 [2] 38 0c }

  condition:
    any of them
}