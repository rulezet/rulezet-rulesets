rule TTP_XOR_QUAD_CurrentVersionRun_0a38 {
  strings:
    $key_0a38 = { 59 57 [2] 7d 59 [2] 56 75 [2] 78 57 [2] 6c 4c [2] 63 56 [2] 7d 4b [2] 7f 4a [2] 64 4c [2] 78 4b [2] 64 64 }

  condition:
    any of them
}