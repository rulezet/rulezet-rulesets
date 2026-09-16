rule TTP_XOR_QUAD_CurrentVersionRun_2241 {
  strings:
    $key_2241 = { 71 2e [2] 55 20 [2] 7e 0c [2] 50 2e [2] 44 35 [2] 4b 2f [2] 55 32 [2] 57 33 [2] 4c 35 [2] 50 32 [2] 4c 1d }

  condition:
    any of them
}