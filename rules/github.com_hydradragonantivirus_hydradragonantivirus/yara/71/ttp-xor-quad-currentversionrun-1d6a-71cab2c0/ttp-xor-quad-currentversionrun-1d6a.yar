rule TTP_XOR_QUAD_CurrentVersionRun_1d6a {
  strings:
    $key_1d6a = { 4e 05 [2] 6a 0b [2] 41 27 [2] 6f 05 [2] 7b 1e [2] 74 04 [2] 6a 19 [2] 68 18 [2] 73 1e [2] 6f 19 [2] 73 36 }

  condition:
    any of them
}