rule TTP_XOR_QUAD_CurrentVersionRun_1a05 {
  strings:
    $key_1a05 = { 49 6a [2] 6d 64 [2] 46 48 [2] 68 6a [2] 7c 71 [2] 73 6b [2] 6d 76 [2] 6f 77 [2] 74 71 [2] 68 76 [2] 74 59 }

  condition:
    any of them
}