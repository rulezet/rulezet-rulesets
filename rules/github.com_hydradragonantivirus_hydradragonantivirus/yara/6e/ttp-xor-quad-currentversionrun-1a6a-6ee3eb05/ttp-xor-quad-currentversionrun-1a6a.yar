rule TTP_XOR_QUAD_CurrentVersionRun_1a6a {
  strings:
    $key_1a6a = { 49 05 [2] 6d 0b [2] 46 27 [2] 68 05 [2] 7c 1e [2] 73 04 [2] 6d 19 [2] 6f 18 [2] 74 1e [2] 68 19 [2] 74 36 }

  condition:
    any of them
}