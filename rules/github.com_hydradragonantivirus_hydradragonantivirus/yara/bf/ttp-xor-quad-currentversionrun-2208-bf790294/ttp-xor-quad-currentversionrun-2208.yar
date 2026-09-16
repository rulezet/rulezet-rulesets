rule TTP_XOR_QUAD_CurrentVersionRun_2208 {
  strings:
    $key_2208 = { 71 67 [2] 55 69 [2] 7e 45 [2] 50 67 [2] 44 7c [2] 4b 66 [2] 55 7b [2] 57 7a [2] 4c 7c [2] 50 7b [2] 4c 54 }

  condition:
    any of them
}