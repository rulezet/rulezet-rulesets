rule TTP_XOR_QUAD_CurrentVersionRun_58ec {
  strings:
    $key_58ec = { 0b 83 [2] 2f 8d [2] 04 a1 [2] 2a 83 [2] 3e 98 [2] 31 82 [2] 2f 9f [2] 2d 9e [2] 36 98 [2] 2a 9f [2] 36 b0 }

  condition:
    any of them
}