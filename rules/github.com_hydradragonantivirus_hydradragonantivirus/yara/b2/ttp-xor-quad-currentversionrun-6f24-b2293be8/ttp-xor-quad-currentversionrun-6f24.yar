rule TTP_XOR_QUAD_CurrentVersionRun_6f24 {
  strings:
    $key_6f24 = { 3c 4b [2] 18 45 [2] 33 69 [2] 1d 4b [2] 09 50 [2] 06 4a [2] 18 57 [2] 1a 56 [2] 01 50 [2] 1d 57 [2] 01 78 }

  condition:
    any of them
}