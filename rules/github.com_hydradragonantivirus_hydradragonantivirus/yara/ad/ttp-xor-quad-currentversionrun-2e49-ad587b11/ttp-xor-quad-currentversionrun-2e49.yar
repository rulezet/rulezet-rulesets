rule TTP_XOR_QUAD_CurrentVersionRun_2e49 {
  strings:
    $key_2e49 = { 7d 26 [2] 59 28 [2] 72 04 [2] 5c 26 [2] 48 3d [2] 47 27 [2] 59 3a [2] 5b 3b [2] 40 3d [2] 5c 3a [2] 40 15 }

  condition:
    any of them
}