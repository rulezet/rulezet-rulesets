rule TTP_XOR_QUAD_CurrentVersionRun_3941 {
  strings:
    $key_3941 = { 6a 2e [2] 4e 20 [2] 65 0c [2] 4b 2e [2] 5f 35 [2] 50 2f [2] 4e 32 [2] 4c 33 [2] 57 35 [2] 4b 32 [2] 57 1d }

  condition:
    any of them
}