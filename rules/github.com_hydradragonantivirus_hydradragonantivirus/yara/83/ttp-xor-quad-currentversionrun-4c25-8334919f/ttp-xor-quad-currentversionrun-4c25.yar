rule TTP_XOR_QUAD_CurrentVersionRun_4c25 {
  strings:
    $key_4c25 = { 1f 4a [2] 3b 44 [2] 10 68 [2] 3e 4a [2] 2a 51 [2] 25 4b [2] 3b 56 [2] 39 57 [2] 22 51 [2] 3e 56 [2] 22 79 }

  condition:
    any of them
}