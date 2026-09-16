rule TTP_XOR_QUAD_CurrentVersionRun_4b7d {
  strings:
    $key_4b7d = { 18 12 [2] 3c 1c [2] 17 30 [2] 39 12 [2] 2d 09 [2] 22 13 [2] 3c 0e [2] 3e 0f [2] 25 09 [2] 39 0e [2] 25 21 }

  condition:
    any of them
}