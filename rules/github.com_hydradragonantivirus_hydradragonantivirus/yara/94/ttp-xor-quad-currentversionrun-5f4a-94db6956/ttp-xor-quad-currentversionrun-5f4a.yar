rule TTP_XOR_QUAD_CurrentVersionRun_5f4a {
  strings:
    $key_5f4a = { 0c 25 [2] 28 2b [2] 03 07 [2] 2d 25 [2] 39 3e [2] 36 24 [2] 28 39 [2] 2a 38 [2] 31 3e [2] 2d 39 [2] 31 16 }

  condition:
    any of them
}