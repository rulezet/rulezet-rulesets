rule TTP_XOR_QUAD_CurrentVersionRun_6902 {
  strings:
    $key_6902 = { 3a 6d [2] 1e 63 [2] 35 4f [2] 1b 6d [2] 0f 76 [2] 00 6c [2] 1e 71 [2] 1c 70 [2] 07 76 [2] 1b 71 [2] 07 5e }

  condition:
    any of them
}