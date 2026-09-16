rule TTP_XOR_QUAD_CurrentVersionRun_3112 {
  strings:
    $key_3112 = { 62 7d [2] 46 73 [2] 6d 5f [2] 43 7d [2] 57 66 [2] 58 7c [2] 46 61 [2] 44 60 [2] 5f 66 [2] 43 61 [2] 5f 4e }

  condition:
    any of them
}