rule TTP_XOR_QUAD_CurrentVersionRun_1f6a {
  strings:
    $key_1f6a = { 4c 05 [2] 68 0b [2] 43 27 [2] 6d 05 [2] 79 1e [2] 76 04 [2] 68 19 [2] 6a 18 [2] 71 1e [2] 6d 19 [2] 71 36 }

  condition:
    any of them
}