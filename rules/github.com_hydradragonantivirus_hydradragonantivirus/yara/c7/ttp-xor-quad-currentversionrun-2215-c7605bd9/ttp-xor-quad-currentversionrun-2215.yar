rule TTP_XOR_QUAD_CurrentVersionRun_2215 {
  strings:
    $key_2215 = { 71 7a [2] 55 74 [2] 7e 58 [2] 50 7a [2] 44 61 [2] 4b 7b [2] 55 66 [2] 57 67 [2] 4c 61 [2] 50 66 [2] 4c 49 }

  condition:
    any of them
}