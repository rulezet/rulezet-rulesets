rule TTP_XOR_QUAD_CurrentVersionRun_6738 {
  strings:
    $key_6738 = { 34 57 [2] 10 59 [2] 3b 75 [2] 15 57 [2] 01 4c [2] 0e 56 [2] 10 4b [2] 12 4a [2] 09 4c [2] 15 4b [2] 09 64 }

  condition:
    any of them
}