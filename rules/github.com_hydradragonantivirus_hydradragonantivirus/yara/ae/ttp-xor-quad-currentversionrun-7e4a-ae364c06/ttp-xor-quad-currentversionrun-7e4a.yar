rule TTP_XOR_QUAD_CurrentVersionRun_7e4a {
  strings:
    $key_7e4a = { 2d 25 [2] 09 2b [2] 22 07 [2] 0c 25 [2] 18 3e [2] 17 24 [2] 09 39 [2] 0b 38 [2] 10 3e [2] 0c 39 [2] 10 16 }

  condition:
    any of them
}