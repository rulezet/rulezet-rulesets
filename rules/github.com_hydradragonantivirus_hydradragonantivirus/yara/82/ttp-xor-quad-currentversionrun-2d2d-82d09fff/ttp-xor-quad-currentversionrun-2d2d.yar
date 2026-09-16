rule TTP_XOR_QUAD_CurrentVersionRun_2d2d {
  strings:
    $key_2d2d = { 7e 42 [2] 5a 4c [2] 71 60 [2] 5f 42 [2] 4b 59 [2] 44 43 [2] 5a 5e [2] 58 5f [2] 43 59 [2] 5f 5e [2] 43 71 }

  condition:
    any of them
}