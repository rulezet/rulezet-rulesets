rule TTP_XOR_QUAD_CurrentVersionRun_0a56 {
  strings:
    $key_0a56 = { 59 39 [2] 7d 37 [2] 56 1b [2] 78 39 [2] 6c 22 [2] 63 38 [2] 7d 25 [2] 7f 24 [2] 64 22 [2] 78 25 [2] 64 0a }

  condition:
    any of them
}