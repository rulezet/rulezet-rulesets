rule TTP_XOR_QUAD_CurrentVersionRun_7e33 {
  strings:
    $key_7e33 = { 2d 5c [2] 09 52 [2] 22 7e [2] 0c 5c [2] 18 47 [2] 17 5d [2] 09 40 [2] 0b 41 [2] 10 47 [2] 0c 40 [2] 10 6f }

  condition:
    any of them
}