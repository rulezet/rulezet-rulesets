rule TTP_XOR_QUAD_CurrentVersionRun_2225 {
  strings:
    $key_2225 = { 71 4a [2] 55 44 [2] 7e 68 [2] 50 4a [2] 44 51 [2] 4b 4b [2] 55 56 [2] 57 57 [2] 4c 51 [2] 50 56 [2] 4c 79 }

  condition:
    any of them
}