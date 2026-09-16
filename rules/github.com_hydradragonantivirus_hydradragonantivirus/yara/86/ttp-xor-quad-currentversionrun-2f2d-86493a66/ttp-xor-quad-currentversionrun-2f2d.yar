rule TTP_XOR_QUAD_CurrentVersionRun_2f2d {
  strings:
    $key_2f2d = { 7c 42 [2] 58 4c [2] 73 60 [2] 5d 42 [2] 49 59 [2] 46 43 [2] 58 5e [2] 5a 5f [2] 41 59 [2] 5d 5e [2] 41 71 }

  condition:
    any of them
}