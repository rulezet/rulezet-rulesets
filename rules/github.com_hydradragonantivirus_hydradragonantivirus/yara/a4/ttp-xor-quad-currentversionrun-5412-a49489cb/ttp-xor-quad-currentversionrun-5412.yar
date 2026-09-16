rule TTP_XOR_QUAD_CurrentVersionRun_5412 {
  strings:
    $key_5412 = { 07 7d [2] 23 73 [2] 08 5f [2] 26 7d [2] 32 66 [2] 3d 7c [2] 23 61 [2] 21 60 [2] 3a 66 [2] 26 61 [2] 3a 4e }

  condition:
    any of them
}