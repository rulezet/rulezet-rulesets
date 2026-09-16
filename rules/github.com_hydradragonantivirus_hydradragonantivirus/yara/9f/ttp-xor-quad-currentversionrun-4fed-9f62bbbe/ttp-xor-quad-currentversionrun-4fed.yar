rule TTP_XOR_QUAD_CurrentVersionRun_4fed {
  strings:
    $key_4fed = { 1c 82 [2] 38 8c [2] 13 a0 [2] 3d 82 [2] 29 99 [2] 26 83 [2] 38 9e [2] 3a 9f [2] 21 99 [2] 3d 9e [2] 21 b1 }

  condition:
    any of them
}