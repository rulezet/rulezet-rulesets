rule TTP_XOR_QUAD_CurrentVersionRun_0312 {
  strings:
    $key_0312 = { 50 7d [2] 74 73 [2] 5f 5f [2] 71 7d [2] 65 66 [2] 6a 7c [2] 74 61 [2] 76 60 [2] 6d 66 [2] 71 61 [2] 6d 4e }

  condition:
    any of them
}