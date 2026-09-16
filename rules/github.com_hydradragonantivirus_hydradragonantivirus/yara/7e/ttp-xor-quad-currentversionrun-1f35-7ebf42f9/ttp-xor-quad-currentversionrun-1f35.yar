rule TTP_XOR_QUAD_CurrentVersionRun_1f35 {
  strings:
    $key_1f35 = { 4c 5a [2] 68 54 [2] 43 78 [2] 6d 5a [2] 79 41 [2] 76 5b [2] 68 46 [2] 6a 47 [2] 71 41 [2] 6d 46 [2] 71 69 }

  condition:
    any of them
}