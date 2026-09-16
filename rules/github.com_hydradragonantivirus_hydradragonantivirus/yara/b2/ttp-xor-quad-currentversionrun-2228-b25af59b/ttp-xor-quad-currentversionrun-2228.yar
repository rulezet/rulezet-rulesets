rule TTP_XOR_QUAD_CurrentVersionRun_2228 {
  strings:
    $key_2228 = { 71 47 [2] 55 49 [2] 7e 65 [2] 50 47 [2] 44 5c [2] 4b 46 [2] 55 5b [2] 57 5a [2] 4c 5c [2] 50 5b [2] 4c 74 }

  condition:
    any of them
}