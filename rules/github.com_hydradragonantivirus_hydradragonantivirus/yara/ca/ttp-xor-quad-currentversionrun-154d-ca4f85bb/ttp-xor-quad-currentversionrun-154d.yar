rule TTP_XOR_QUAD_CurrentVersionRun_154d {
  strings:
    $key_154d = { 46 22 [2] 62 2c [2] 49 00 [2] 67 22 [2] 73 39 [2] 7c 23 [2] 62 3e [2] 60 3f [2] 7b 39 [2] 67 3e [2] 7b 11 }

  condition:
    any of them
}