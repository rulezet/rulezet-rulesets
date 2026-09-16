rule TTP_XOR_QUAD_CurrentVersionRun_4828 {
  strings:
    $key_4828 = { 1b 47 [2] 3f 49 [2] 14 65 [2] 3a 47 [2] 2e 5c [2] 21 46 [2] 3f 5b [2] 3d 5a [2] 26 5c [2] 3a 5b [2] 26 74 }

  condition:
    any of them
}