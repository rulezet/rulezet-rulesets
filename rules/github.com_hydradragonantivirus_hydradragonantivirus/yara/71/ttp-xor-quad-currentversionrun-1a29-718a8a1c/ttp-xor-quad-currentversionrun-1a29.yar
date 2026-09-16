rule TTP_XOR_QUAD_CurrentVersionRun_1a29 {
  strings:
    $key_1a29 = { 49 46 [2] 6d 48 [2] 46 64 [2] 68 46 [2] 7c 5d [2] 73 47 [2] 6d 5a [2] 6f 5b [2] 74 5d [2] 68 5a [2] 74 75 }

  condition:
    any of them
}