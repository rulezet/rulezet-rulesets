rule TTP_XOR_QUAD_CurrentVersionRun_2278 {
  strings:
    $key_2278 = { 71 17 [2] 55 19 [2] 7e 35 [2] 50 17 [2] 44 0c [2] 4b 16 [2] 55 0b [2] 57 0a [2] 4c 0c [2] 50 0b [2] 4c 24 }

  condition:
    any of them
}