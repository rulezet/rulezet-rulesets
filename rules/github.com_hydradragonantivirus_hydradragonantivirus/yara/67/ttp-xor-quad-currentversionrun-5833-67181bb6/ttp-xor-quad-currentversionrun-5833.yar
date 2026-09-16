rule TTP_XOR_QUAD_CurrentVersionRun_5833 {
  strings:
    $key_5833 = { 0b 5c [2] 2f 52 [2] 04 7e [2] 2a 5c [2] 3e 47 [2] 31 5d [2] 2f 40 [2] 2d 41 [2] 36 47 [2] 2a 40 [2] 36 6f }

  condition:
    any of them
}