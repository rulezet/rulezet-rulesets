rule TTP_XOR_QUAD_CurrentVersionRun_4841 {
  strings:
    $key_4841 = { 1b 2e [2] 3f 20 [2] 14 0c [2] 3a 2e [2] 2e 35 [2] 21 2f [2] 3f 32 [2] 3d 33 [2] 26 35 [2] 3a 32 [2] 26 1d }

  condition:
    any of them
}