rule TTP_XOR_QUAD_CurrentVersionRun_fe1a {
  strings:
    $key_fe1a = { ad 75 [2] 89 7b [2] a2 57 [2] 8c 75 [2] 98 6e [2] 97 74 [2] 89 69 [2] 8b 68 [2] 90 6e [2] 8c 69 [2] 90 46 }

  condition:
    any of them
}