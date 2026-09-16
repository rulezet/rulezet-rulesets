rule TTP_XOR_QUAD_CurrentVersionRun_1f29 {
  strings:
    $key_1f29 = { 4c 46 [2] 68 48 [2] 43 64 [2] 6d 46 [2] 79 5d [2] 76 47 [2] 68 5a [2] 6a 5b [2] 71 5d [2] 6d 5a [2] 71 75 }

  condition:
    any of them
}