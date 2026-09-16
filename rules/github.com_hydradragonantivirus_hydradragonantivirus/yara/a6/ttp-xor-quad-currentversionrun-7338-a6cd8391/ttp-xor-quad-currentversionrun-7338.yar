rule TTP_XOR_QUAD_CurrentVersionRun_7338 {
  strings:
    $key_7338 = { 20 57 [2] 04 59 [2] 2f 75 [2] 01 57 [2] 15 4c [2] 1a 56 [2] 04 4b [2] 06 4a [2] 1d 4c [2] 01 4b [2] 1d 64 }

  condition:
    any of them
}