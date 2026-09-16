rule TTP_XOR_QUAD_CurrentVersionRun_e863 {
  strings:
    $key_e863 = { bb 0c [2] 9f 02 [2] b4 2e [2] 9a 0c [2] 8e 17 [2] 81 0d [2] 9f 10 [2] 9d 11 [2] 86 17 [2] 9a 10 [2] 86 3f }

  condition:
    any of them
}