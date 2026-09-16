rule TTP_XOR_QUAD_CurrentVersionRun_6724 {
  strings:
    $key_6724 = { 34 4b [2] 10 45 [2] 3b 69 [2] 15 4b [2] 01 50 [2] 0e 4a [2] 10 57 [2] 12 56 [2] 09 50 [2] 15 57 [2] 09 78 }

  condition:
    any of them
}