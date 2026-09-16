rule TTP_XOR_QUAD_CurrentVersionRun_1a41 {
  strings:
    $key_1a41 = { 49 2e [2] 6d 20 [2] 46 0c [2] 68 2e [2] 7c 35 [2] 73 2f [2] 6d 32 [2] 6f 33 [2] 74 35 [2] 68 32 [2] 74 1d }

  condition:
    any of them
}