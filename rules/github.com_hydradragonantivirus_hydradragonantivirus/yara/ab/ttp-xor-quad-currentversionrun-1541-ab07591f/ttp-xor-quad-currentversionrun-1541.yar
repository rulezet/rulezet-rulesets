rule TTP_XOR_QUAD_CurrentVersionRun_1541 {
  strings:
    $key_1541 = { 46 2e [2] 62 20 [2] 49 0c [2] 67 2e [2] 73 35 [2] 7c 2f [2] 62 32 [2] 60 33 [2] 7b 35 [2] 67 32 [2] 7b 1d }

  condition:
    any of them
}