rule TTP_XOR_QUAD_CurrentVersionRun_1f34 {
  strings:
    $key_1f34 = { 4c 5b [2] 68 55 [2] 43 79 [2] 6d 5b [2] 79 40 [2] 76 5a [2] 68 47 [2] 6a 46 [2] 71 40 [2] 6d 47 [2] 71 68 }

  condition:
    any of them
}