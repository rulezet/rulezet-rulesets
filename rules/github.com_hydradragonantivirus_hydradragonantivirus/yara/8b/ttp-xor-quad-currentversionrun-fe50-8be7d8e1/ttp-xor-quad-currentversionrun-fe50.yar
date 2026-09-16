rule TTP_XOR_QUAD_CurrentVersionRun_fe50 {
  strings:
    $key_fe50 = { ad 3f [2] 89 31 [2] a2 1d [2] 8c 3f [2] 98 24 [2] 97 3e [2] 89 23 [2] 8b 22 [2] 90 24 [2] 8c 23 [2] 90 0c }

  condition:
    any of them
}