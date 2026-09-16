rule TTP_XOR_QUAD_CurrentVersionRun_6031 {
  strings:
    $key_6031 = { 33 5e [2] 17 50 [2] 3c 7c [2] 12 5e [2] 06 45 [2] 09 5f [2] 17 42 [2] 15 43 [2] 0e 45 [2] 12 42 [2] 0e 6d }

  condition:
    any of them
}