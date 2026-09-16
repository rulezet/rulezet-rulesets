rule TTP_XOR_QUAD_CurrentVersionRun_fe1b {
  strings:
    $key_fe1b = { ad 74 [2] 89 7a [2] a2 56 [2] 8c 74 [2] 98 6f [2] 97 75 [2] 89 68 [2] 8b 69 [2] 90 6f [2] 8c 68 [2] 90 47 }

  condition:
    any of them
}