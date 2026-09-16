rule TTP_XOR_QUAD_CurrentVersionRun_741f {
  strings:
    $key_741f = { 27 70 [2] 03 7e [2] 28 52 [2] 06 70 [2] 12 6b [2] 1d 71 [2] 03 6c [2] 01 6d [2] 1a 6b [2] 06 6c [2] 1a 43 }

  condition:
    any of them
}