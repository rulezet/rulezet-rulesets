rule TTP_XOR_QUAD_CurrentVersionRun_1d2d {
  strings:
    $key_1d2d = { 4e 42 [2] 6a 4c [2] 41 60 [2] 6f 42 [2] 7b 59 [2] 74 43 [2] 6a 5e [2] 68 5f [2] 73 59 [2] 6f 5e [2] 73 71 }

  condition:
    any of them
}