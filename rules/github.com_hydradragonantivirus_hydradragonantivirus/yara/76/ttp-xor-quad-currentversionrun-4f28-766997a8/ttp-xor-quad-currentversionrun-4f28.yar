rule TTP_XOR_QUAD_CurrentVersionRun_4f28 {
  strings:
    $key_4f28 = { 1c 47 [2] 38 49 [2] 13 65 [2] 3d 47 [2] 29 5c [2] 26 46 [2] 38 5b [2] 3a 5a [2] 21 5c [2] 3d 5b [2] 21 74 }

  condition:
    any of them
}