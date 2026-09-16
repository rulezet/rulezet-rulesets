rule TTP_XOR_QUAD_CurrentVersionRun_0341 {
  strings:
    $key_0341 = { 50 2e [2] 74 20 [2] 5f 0c [2] 71 2e [2] 65 35 [2] 6a 2f [2] 74 32 [2] 76 33 [2] 6d 35 [2] 71 32 [2] 6d 1d }

  condition:
    any of them
}