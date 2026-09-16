rule TTP_XOR_QUAD_CurrentVersionRun_fe1c {
  strings:
    $key_fe1c = { ad 73 [2] 89 7d [2] a2 51 [2] 8c 73 [2] 98 68 [2] 97 72 [2] 89 6f [2] 8b 6e [2] 90 68 [2] 8c 6f [2] 90 40 }

  condition:
    any of them
}