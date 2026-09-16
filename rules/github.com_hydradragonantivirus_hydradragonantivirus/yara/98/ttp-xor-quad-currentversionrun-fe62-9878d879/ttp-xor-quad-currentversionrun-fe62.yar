rule TTP_XOR_QUAD_CurrentVersionRun_fe62 {
  strings:
    $key_fe62 = { ad 0d [2] 89 03 [2] a2 2f [2] 8c 0d [2] 98 16 [2] 97 0c [2] 89 11 [2] 8b 10 [2] 90 16 [2] 8c 11 [2] 90 3e }

  condition:
    any of them
}