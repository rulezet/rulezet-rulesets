rule TTP_XOR_QUAD_CurrentVersionRun_fe20 {
  strings:
    $key_fe20 = { ad 4f [2] 89 41 [2] a2 6d [2] 8c 4f [2] 98 54 [2] 97 4e [2] 89 53 [2] 8b 52 [2] 90 54 [2] 8c 53 [2] 90 7c }

  condition:
    any of them
}