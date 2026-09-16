rule TTP_XOR_QUAD_CurrentVersionRun_1333 {
  strings:
    $key_1333 = { 40 5c [2] 64 52 [2] 4f 7e [2] 61 5c [2] 75 47 [2] 7a 5d [2] 64 40 [2] 66 41 [2] 7d 47 [2] 61 40 [2] 7d 6f }

  condition:
    any of them
}