rule TTP_XOR_QUAD_CurrentVersionRun_474c {
  strings:
    $key_474c = { 14 23 [2] 30 2d [2] 1b 01 [2] 35 23 [2] 21 38 [2] 2e 22 [2] 30 3f [2] 32 3e [2] 29 38 [2] 35 3f [2] 29 10 }

  condition:
    any of them
}