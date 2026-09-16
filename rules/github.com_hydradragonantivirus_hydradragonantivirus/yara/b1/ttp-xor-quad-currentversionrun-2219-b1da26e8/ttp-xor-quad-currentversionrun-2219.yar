rule TTP_XOR_QUAD_CurrentVersionRun_2219 {
  strings:
    $key_2219 = { 71 76 [2] 55 78 [2] 7e 54 [2] 50 76 [2] 44 6d [2] 4b 77 [2] 55 6a [2] 57 6b [2] 4c 6d [2] 50 6a [2] 4c 45 }

  condition:
    any of them
}