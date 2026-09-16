rule TTP_XOR_QUAD_CurrentVersionRun_1638 {
  strings:
    $key_1638 = { 45 57 [2] 61 59 [2] 4a 75 [2] 64 57 [2] 70 4c [2] 7f 56 [2] 61 4b [2] 63 4a [2] 78 4c [2] 64 4b [2] 78 64 }

  condition:
    any of them
}