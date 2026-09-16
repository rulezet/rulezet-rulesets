rule TTP_XOR_QUAD_CurrentVersionRun_5f28 {
  strings:
    $key_5f28 = { 0c 47 [2] 28 49 [2] 03 65 [2] 2d 47 [2] 39 5c [2] 36 46 [2] 28 5b [2] 2a 5a [2] 31 5c [2] 2d 5b [2] 31 74 }

  condition:
    any of them
}