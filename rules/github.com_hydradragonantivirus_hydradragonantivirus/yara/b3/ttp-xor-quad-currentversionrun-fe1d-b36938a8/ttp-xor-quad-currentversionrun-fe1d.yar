rule TTP_XOR_QUAD_CurrentVersionRun_fe1d {
  strings:
    $key_fe1d = { ad 72 [2] 89 7c [2] a2 50 [2] 8c 72 [2] 98 69 [2] 97 73 [2] 89 6e [2] 8b 6f [2] 90 69 [2] 8c 6e [2] 90 41 }

  condition:
    any of them
}