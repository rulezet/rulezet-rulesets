rule TTP_XOR_QUAD_CurrentVersionRun_7638 {
  strings:
    $key_7638 = { 25 57 [2] 01 59 [2] 2a 75 [2] 04 57 [2] 10 4c [2] 1f 56 [2] 01 4b [2] 03 4a [2] 18 4c [2] 04 4b [2] 18 64 }

  condition:
    any of them
}