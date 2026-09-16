rule TTP_XOR_QUAD_CurrentVersionRun_1f12 {
  strings:
    $key_1f12 = { 4c 7d [2] 68 73 [2] 43 5f [2] 6d 7d [2] 79 66 [2] 76 7c [2] 68 61 [2] 6a 60 [2] 71 66 [2] 6d 61 [2] 71 4e }

  condition:
    any of them
}