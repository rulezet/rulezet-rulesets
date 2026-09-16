rule TTP_XOR_QUAD_CurrentVersionRun_4c38 {
  strings:
    $key_4c38 = { 1f 57 [2] 3b 59 [2] 10 75 [2] 3e 57 [2] 2a 4c [2] 25 56 [2] 3b 4b [2] 39 4a [2] 22 4c [2] 3e 4b [2] 22 64 }

  condition:
    any of them
}