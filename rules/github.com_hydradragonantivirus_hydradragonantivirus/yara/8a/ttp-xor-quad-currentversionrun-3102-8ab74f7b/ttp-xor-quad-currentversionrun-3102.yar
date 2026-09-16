rule TTP_XOR_QUAD_CurrentVersionRun_3102 {
  strings:
    $key_3102 = { 62 6d [2] 46 63 [2] 6d 4f [2] 43 6d [2] 57 76 [2] 58 6c [2] 46 71 [2] 44 70 [2] 5f 76 [2] 43 71 [2] 5f 5e }

  condition:
    any of them
}