rule TTP_XOR_QUAD_CurrentVersionRun_064d {
  strings:
    $key_064d = { 55 22 [2] 71 2c [2] 5a 00 [2] 74 22 [2] 60 39 [2] 6f 23 [2] 71 3e [2] 73 3f [2] 68 39 [2] 74 3e [2] 68 11 }

  condition:
    any of them
}