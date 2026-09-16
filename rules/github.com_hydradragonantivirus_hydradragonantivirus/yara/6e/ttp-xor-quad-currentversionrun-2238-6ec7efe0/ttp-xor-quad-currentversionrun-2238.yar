rule TTP_XOR_QUAD_CurrentVersionRun_2238 {
  strings:
    $key_2238 = { 71 57 [2] 55 59 [2] 7e 75 [2] 50 57 [2] 44 4c [2] 4b 56 [2] 55 4b [2] 57 4a [2] 4c 4c [2] 50 4b [2] 4c 64 }

  condition:
    any of them
}