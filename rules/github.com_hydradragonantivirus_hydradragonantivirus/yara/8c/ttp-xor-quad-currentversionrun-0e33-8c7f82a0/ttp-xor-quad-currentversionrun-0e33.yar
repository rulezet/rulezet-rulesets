rule TTP_XOR_QUAD_CurrentVersionRun_0e33 {
  strings:
    $key_0e33 = { 5d 5c [2] 79 52 [2] 52 7e [2] 7c 5c [2] 68 47 [2] 67 5d [2] 79 40 [2] 7b 41 [2] 60 47 [2] 7c 40 [2] 60 6f }

  condition:
    any of them
}