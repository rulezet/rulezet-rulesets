rule TTP_XOR_QUAD_CurrentVersionRun_fe32 {
  strings:
    $key_fe32 = { ad 5d [2] 89 53 [2] a2 7f [2] 8c 5d [2] 98 46 [2] 97 5c [2] 89 41 [2] 8b 40 [2] 90 46 [2] 8c 41 [2] 90 6e }

  condition:
    any of them
}