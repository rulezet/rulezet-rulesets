rule TTP_XOR_QUAD_CurrentVersionRun_1b6a {
  strings:
    $key_1b6a = { 48 05 [2] 6c 0b [2] 47 27 [2] 69 05 [2] 7d 1e [2] 72 04 [2] 6c 19 [2] 6e 18 [2] 75 1e [2] 69 19 [2] 75 36 }

  condition:
    any of them
}