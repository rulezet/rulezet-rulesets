rule TTP_XOR_QUAD_CurrentVersionRun_4533 {
  strings:
    $key_4533 = { 16 5c [2] 32 52 [2] 19 7e [2] 37 5c [2] 23 47 [2] 2c 5d [2] 32 40 [2] 30 41 [2] 2b 47 [2] 37 40 [2] 2b 6f }

  condition:
    any of them
}