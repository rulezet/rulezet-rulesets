rule TTP_XOR_QUAD_CurrentVersionRun_2d6a {
  strings:
    $key_2d6a = { 7e 05 [2] 5a 0b [2] 71 27 [2] 5f 05 [2] 4b 1e [2] 44 04 [2] 5a 19 [2] 58 18 [2] 43 1e [2] 5f 19 [2] 43 36 }

  condition:
    any of them
}