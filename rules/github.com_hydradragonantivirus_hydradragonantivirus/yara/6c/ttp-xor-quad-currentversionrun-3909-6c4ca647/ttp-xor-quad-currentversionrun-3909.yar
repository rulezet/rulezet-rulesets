rule TTP_XOR_QUAD_CurrentVersionRun_3909 {
  strings:
    $key_3909 = { 6a 66 [2] 4e 68 [2] 65 44 [2] 4b 66 [2] 5f 7d [2] 50 67 [2] 4e 7a [2] 4c 7b [2] 57 7d [2] 4b 7a [2] 57 55 }

  condition:
    any of them
}