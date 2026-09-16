rule TTP_XOR_QUAD_CurrentVersionRun_fe7a {
  strings:
    $key_fe7a = { ad 15 [2] 89 1b [2] a2 37 [2] 8c 15 [2] 98 0e [2] 97 14 [2] 89 09 [2] 8b 08 [2] 90 0e [2] 8c 09 [2] 90 26 }

  condition:
    any of them
}