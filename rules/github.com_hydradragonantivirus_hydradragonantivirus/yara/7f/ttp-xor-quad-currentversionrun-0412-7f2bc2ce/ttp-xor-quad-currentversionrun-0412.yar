rule TTP_XOR_QUAD_CurrentVersionRun_0412 {
  strings:
    $key_0412 = { 57 7d [2] 73 73 [2] 58 5f [2] 76 7d [2] 62 66 [2] 6d 7c [2] 73 61 [2] 71 60 [2] 6a 66 [2] 76 61 [2] 6a 4e }

  condition:
    any of them
}