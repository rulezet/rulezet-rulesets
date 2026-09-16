rule TTP_XOR_QUAD_CurrentVersionRun_4b6a {
  strings:
    $key_4b6a = { 18 05 [2] 3c 0b [2] 17 27 [2] 39 05 [2] 2d 1e [2] 22 04 [2] 3c 19 [2] 3e 18 [2] 25 1e [2] 39 19 [2] 25 36 }

  condition:
    any of them
}