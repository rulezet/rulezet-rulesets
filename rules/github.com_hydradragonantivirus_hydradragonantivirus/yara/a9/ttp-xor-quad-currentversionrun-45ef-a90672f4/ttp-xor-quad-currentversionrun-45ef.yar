rule TTP_XOR_QUAD_CurrentVersionRun_45ef {
  strings:
    $key_45ef = { 16 80 [2] 32 8e [2] 19 a2 [2] 37 80 [2] 23 9b [2] 2c 81 [2] 32 9c [2] 30 9d [2] 2b 9b [2] 37 9c [2] 2b b3 }

  condition:
    any of them
}