rule TTP_XOR_QUAD_CurrentVersionRun_1750 {
  strings:
    $key_1750 = { 44 3f [2] 60 31 [2] 4b 1d [2] 65 3f [2] 71 24 [2] 7e 3e [2] 60 23 [2] 62 22 [2] 79 24 [2] 65 23 [2] 79 0c }

  condition:
    any of them
}