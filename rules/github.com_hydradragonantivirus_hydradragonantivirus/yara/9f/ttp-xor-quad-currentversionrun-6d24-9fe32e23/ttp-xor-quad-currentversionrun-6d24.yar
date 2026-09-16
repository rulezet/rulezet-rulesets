rule TTP_XOR_QUAD_CurrentVersionRun_6d24 {
  strings:
    $key_6d24 = { 3e 4b [2] 1a 45 [2] 31 69 [2] 1f 4b [2] 0b 50 [2] 04 4a [2] 1a 57 [2] 18 56 [2] 03 50 [2] 1f 57 [2] 03 78 }

  condition:
    any of them
}