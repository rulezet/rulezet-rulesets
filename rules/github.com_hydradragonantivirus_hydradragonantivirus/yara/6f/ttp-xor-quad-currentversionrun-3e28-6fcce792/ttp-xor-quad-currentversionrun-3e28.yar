rule TTP_XOR_QUAD_CurrentVersionRun_3e28 {
  strings:
    $key_3e28 = { 6d 47 [2] 49 49 [2] 62 65 [2] 4c 47 [2] 58 5c [2] 57 46 [2] 49 5b [2] 4b 5a [2] 50 5c [2] 4c 5b [2] 50 74 }

  condition:
    any of them
}