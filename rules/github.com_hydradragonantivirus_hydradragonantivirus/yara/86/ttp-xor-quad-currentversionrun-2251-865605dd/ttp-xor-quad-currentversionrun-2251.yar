rule TTP_XOR_QUAD_CurrentVersionRun_2251 {
  strings:
    $key_2251 = { 71 3e [2] 55 30 [2] 7e 1c [2] 50 3e [2] 44 25 [2] 4b 3f [2] 55 22 [2] 57 23 [2] 4c 25 [2] 50 22 [2] 4c 0d }

  condition:
    any of them
}