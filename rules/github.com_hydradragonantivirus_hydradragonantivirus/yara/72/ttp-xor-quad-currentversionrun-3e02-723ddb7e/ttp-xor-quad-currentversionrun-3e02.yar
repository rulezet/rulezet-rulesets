rule TTP_XOR_QUAD_CurrentVersionRun_3e02 {
  strings:
    $key_3e02 = { 6d 6d [2] 49 63 [2] 62 4f [2] 4c 6d [2] 58 76 [2] 57 6c [2] 49 71 [2] 4b 70 [2] 50 76 [2] 4c 71 [2] 50 5e }

  condition:
    any of them
}