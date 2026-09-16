rule TTP_XOR_QUAD_CurrentVersionRun_3e19 {
  strings:
    $key_3e19 = { 6d 76 [2] 49 78 [2] 62 54 [2] 4c 76 [2] 58 6d [2] 57 77 [2] 49 6a [2] 4b 6b [2] 50 6d [2] 4c 6a [2] 50 45 }

  condition:
    any of them
}