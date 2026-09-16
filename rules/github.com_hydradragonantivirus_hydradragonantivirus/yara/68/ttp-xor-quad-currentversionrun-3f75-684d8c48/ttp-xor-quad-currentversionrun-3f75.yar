rule TTP_XOR_QUAD_CurrentVersionRun_3f75 {
  strings:
    $key_3f75 = { 6c 1a [2] 48 14 [2] 63 38 [2] 4d 1a [2] 59 01 [2] 56 1b [2] 48 06 [2] 4a 07 [2] 51 01 [2] 4d 06 [2] 51 29 }

  condition:
    any of them
}