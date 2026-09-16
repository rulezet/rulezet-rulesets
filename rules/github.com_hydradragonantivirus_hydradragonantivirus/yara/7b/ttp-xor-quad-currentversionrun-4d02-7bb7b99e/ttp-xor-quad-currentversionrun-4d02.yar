rule TTP_XOR_QUAD_CurrentVersionRun_4d02 {
  strings:
    $key_4d02 = { 1e 6d [2] 3a 63 [2] 11 4f [2] 3f 6d [2] 2b 76 [2] 24 6c [2] 3a 71 [2] 38 70 [2] 23 76 [2] 3f 71 [2] 23 5e }

  condition:
    any of them
}