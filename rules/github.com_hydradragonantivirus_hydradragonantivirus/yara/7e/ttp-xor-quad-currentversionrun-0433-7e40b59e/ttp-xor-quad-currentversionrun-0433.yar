rule TTP_XOR_QUAD_CurrentVersionRun_0433 {
  strings:
    $key_0433 = { 57 5c [2] 73 52 [2] 58 7e [2] 76 5c [2] 62 47 [2] 6d 5d [2] 73 40 [2] 71 41 [2] 6a 47 [2] 76 40 [2] 6a 6f }

  condition:
    any of them
}