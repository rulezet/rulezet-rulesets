rule TTP_XOR_QUAD_CurrentVersionRun_2741 {
  strings:
    $key_2741 = { 74 2e [2] 50 20 [2] 7b 0c [2] 55 2e [2] 41 35 [2] 4e 2f [2] 50 32 [2] 52 33 [2] 49 35 [2] 55 32 [2] 49 1d }

  condition:
    any of them
}