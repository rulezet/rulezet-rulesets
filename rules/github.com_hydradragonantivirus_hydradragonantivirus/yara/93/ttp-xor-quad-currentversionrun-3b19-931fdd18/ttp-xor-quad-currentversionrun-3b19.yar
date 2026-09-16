rule TTP_XOR_QUAD_CurrentVersionRun_3b19 {
  strings:
    $key_3b19 = { 68 76 [2] 4c 78 [2] 67 54 [2] 49 76 [2] 5d 6d [2] 52 77 [2] 4c 6a [2] 4e 6b [2] 55 6d [2] 49 6a [2] 55 45 }

  condition:
    any of them
}