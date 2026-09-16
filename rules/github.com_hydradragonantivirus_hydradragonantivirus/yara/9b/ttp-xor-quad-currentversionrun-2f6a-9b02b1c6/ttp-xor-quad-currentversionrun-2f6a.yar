rule TTP_XOR_QUAD_CurrentVersionRun_2f6a {
  strings:
    $key_2f6a = { 7c 05 [2] 58 0b [2] 73 27 [2] 5d 05 [2] 49 1e [2] 46 04 [2] 58 19 [2] 5a 18 [2] 41 1e [2] 5d 19 [2] 41 36 }

  condition:
    any of them
}