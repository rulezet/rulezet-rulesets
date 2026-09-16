rule TTP_XOR_QUAD_CurrentVersionRun_3e41 {
  strings:
    $key_3e41 = { 6d 2e [2] 49 20 [2] 62 0c [2] 4c 2e [2] 58 35 [2] 57 2f [2] 49 32 [2] 4b 33 [2] 50 35 [2] 4c 32 [2] 50 1d }

  condition:
    any of them
}