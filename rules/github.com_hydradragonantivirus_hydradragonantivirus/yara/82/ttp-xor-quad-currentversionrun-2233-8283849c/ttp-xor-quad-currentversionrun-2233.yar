rule TTP_XOR_QUAD_CurrentVersionRun_2233 {
  strings:
    $key_2233 = { 71 5c [2] 55 52 [2] 7e 7e [2] 50 5c [2] 44 47 [2] 4b 5d [2] 55 40 [2] 57 41 [2] 4c 47 [2] 50 40 [2] 4c 6f }

  condition:
    any of them
}