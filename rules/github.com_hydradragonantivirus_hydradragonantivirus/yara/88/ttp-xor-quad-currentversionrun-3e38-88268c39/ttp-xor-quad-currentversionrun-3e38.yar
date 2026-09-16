rule TTP_XOR_QUAD_CurrentVersionRun_3e38 {
  strings:
    $key_3e38 = { 6d 57 [2] 49 59 [2] 62 75 [2] 4c 57 [2] 58 4c [2] 57 56 [2] 49 4b [2] 4b 4a [2] 50 4c [2] 4c 4b [2] 50 64 }

  condition:
    any of them
}