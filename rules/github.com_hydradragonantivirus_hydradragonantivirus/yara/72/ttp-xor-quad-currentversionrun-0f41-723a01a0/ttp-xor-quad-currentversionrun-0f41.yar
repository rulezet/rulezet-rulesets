rule TTP_XOR_QUAD_CurrentVersionRun_0f41 {
  strings:
    $key_0f41 = { 5c 2e [2] 78 20 [2] 53 0c [2] 7d 2e [2] 69 35 [2] 66 2f [2] 78 32 [2] 7a 33 [2] 61 35 [2] 7d 32 [2] 61 1d }

  condition:
    any of them
}