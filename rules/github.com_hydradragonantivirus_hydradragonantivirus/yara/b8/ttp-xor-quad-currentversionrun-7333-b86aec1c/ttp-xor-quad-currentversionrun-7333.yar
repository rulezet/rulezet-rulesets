rule TTP_XOR_QUAD_CurrentVersionRun_7333 {
  strings:
    $key_7333 = { 20 5c [2] 04 52 [2] 2f 7e [2] 01 5c [2] 15 47 [2] 1a 5d [2] 04 40 [2] 06 41 [2] 1d 47 [2] 01 40 [2] 1d 6f }

  condition:
    any of them
}