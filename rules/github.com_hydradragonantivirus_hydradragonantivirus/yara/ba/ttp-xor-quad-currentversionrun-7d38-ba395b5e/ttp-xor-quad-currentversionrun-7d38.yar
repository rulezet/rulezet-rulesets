rule TTP_XOR_QUAD_CurrentVersionRun_7d38 {
  strings:
    $key_7d38 = { 2e 57 [2] 0a 59 [2] 21 75 [2] 0f 57 [2] 1b 4c [2] 14 56 [2] 0a 4b [2] 08 4a [2] 13 4c [2] 0f 4b [2] 13 64 }

  condition:
    any of them
}