rule TTP_XOR_QUAD_CurrentVersionRun_4e33 {
  strings:
    $key_4e33 = { 1d 5c [2] 39 52 [2] 12 7e [2] 3c 5c [2] 28 47 [2] 27 5d [2] 39 40 [2] 3b 41 [2] 20 47 [2] 3c 40 [2] 20 6f }

  condition:
    any of them
}