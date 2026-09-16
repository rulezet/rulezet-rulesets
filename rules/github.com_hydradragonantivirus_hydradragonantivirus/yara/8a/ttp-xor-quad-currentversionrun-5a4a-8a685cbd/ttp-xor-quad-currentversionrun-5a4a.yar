rule TTP_XOR_QUAD_CurrentVersionRun_5a4a {
  strings:
    $key_5a4a = { 09 25 [2] 2d 2b [2] 06 07 [2] 28 25 [2] 3c 3e [2] 33 24 [2] 2d 39 [2] 2f 38 [2] 34 3e [2] 28 39 [2] 34 16 }

  condition:
    any of them
}