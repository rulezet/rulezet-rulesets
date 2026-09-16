rule TTP_XOR_QUAD_CurrentVersionRun_066a {
  strings:
    $key_066a = { 55 05 [2] 71 0b [2] 5a 27 [2] 74 05 [2] 60 1e [2] 6f 04 [2] 71 19 [2] 73 18 [2] 68 1e [2] 74 19 [2] 68 36 }

  condition:
    any of them
}