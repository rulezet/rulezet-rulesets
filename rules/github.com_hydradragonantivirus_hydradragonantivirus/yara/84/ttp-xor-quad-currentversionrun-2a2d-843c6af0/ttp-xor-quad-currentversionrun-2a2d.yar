rule TTP_XOR_QUAD_CurrentVersionRun_2a2d {
  strings:
    $key_2a2d = { 79 42 [2] 5d 4c [2] 76 60 [2] 58 42 [2] 4c 59 [2] 43 43 [2] 5d 5e [2] 5f 5f [2] 44 59 [2] 58 5e [2] 44 71 }

  condition:
    any of them
}