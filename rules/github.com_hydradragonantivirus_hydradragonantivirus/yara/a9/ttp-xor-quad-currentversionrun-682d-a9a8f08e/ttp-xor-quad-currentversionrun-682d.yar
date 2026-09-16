rule TTP_XOR_QUAD_CurrentVersionRun_682d {
  strings:
    $key_682d = { 3b 42 [2] 1f 4c [2] 34 60 [2] 1a 42 [2] 0e 59 [2] 01 43 [2] 1f 5e [2] 1d 5f [2] 06 59 [2] 1a 5e [2] 06 71 }

  condition:
    any of them
}