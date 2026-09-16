rule TTP_XOR_QUAD_CurrentVersionRun_2218 {
  strings:
    $key_2218 = { 71 77 [2] 55 79 [2] 7e 55 [2] 50 77 [2] 44 6c [2] 4b 76 [2] 55 6b [2] 57 6a [2] 4c 6c [2] 50 6b [2] 4c 44 }

  condition:
    any of them
}