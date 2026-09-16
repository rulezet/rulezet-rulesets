rule TTP_XOR_QUAD_CurrentVersionRun_2751 {
  strings:
    $key_2751 = { 74 3e [2] 50 30 [2] 7b 1c [2] 55 3e [2] 41 25 [2] 4e 3f [2] 50 22 [2] 52 23 [2] 49 25 [2] 55 22 [2] 49 0d }

  condition:
    any of them
}