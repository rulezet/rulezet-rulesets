rule TTP_XOR_QUAD_CurrentVersionRun_fe40 {
  strings:
    $key_fe40 = { ad 2f [2] 89 21 [2] a2 0d [2] 8c 2f [2] 98 34 [2] 97 2e [2] 89 33 [2] 8b 32 [2] 90 34 [2] 8c 33 [2] 90 1c }

  condition:
    any of them
}