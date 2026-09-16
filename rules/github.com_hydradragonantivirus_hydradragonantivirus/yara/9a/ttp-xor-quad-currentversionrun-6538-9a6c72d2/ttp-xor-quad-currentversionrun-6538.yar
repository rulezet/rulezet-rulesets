rule TTP_XOR_QUAD_CurrentVersionRun_6538 {
  strings:
    $key_6538 = { 36 57 [2] 12 59 [2] 39 75 [2] 17 57 [2] 03 4c [2] 0c 56 [2] 12 4b [2] 10 4a [2] 0b 4c [2] 17 4b [2] 0b 64 }

  condition:
    any of them
}