rule TTP_XOR_QUAD_CurrentVersionRun_1e33 {
  strings:
    $key_1e33 = { 4d 5c [2] 69 52 [2] 42 7e [2] 6c 5c [2] 78 47 [2] 77 5d [2] 69 40 [2] 6b 41 [2] 70 47 [2] 6c 40 [2] 70 6f }

  condition:
    any of them
}