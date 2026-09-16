rule TTP_XOR_QUAD_CurrentVersionRun_1659 {
  strings:
    $key_1659 = { 45 36 [2] 61 38 [2] 4a 14 [2] 64 36 [2] 70 2d [2] 7f 37 [2] 61 2a [2] 63 2b [2] 78 2d [2] 64 2a [2] 78 05 }

  condition:
    any of them
}