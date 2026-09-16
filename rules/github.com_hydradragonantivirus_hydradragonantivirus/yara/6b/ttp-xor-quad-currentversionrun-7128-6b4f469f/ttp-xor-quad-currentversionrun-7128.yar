rule TTP_XOR_QUAD_CurrentVersionRun_7128 {
  strings:
    $key_7128 = { 22 47 [2] 06 49 [2] 2d 65 [2] 03 47 [2] 17 5c [2] 18 46 [2] 06 5b [2] 04 5a [2] 1f 5c [2] 03 5b [2] 1f 74 }

  condition:
    any of them
}