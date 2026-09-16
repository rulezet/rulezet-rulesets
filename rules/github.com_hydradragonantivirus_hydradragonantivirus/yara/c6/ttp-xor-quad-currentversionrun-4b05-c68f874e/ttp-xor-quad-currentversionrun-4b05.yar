rule TTP_XOR_QUAD_CurrentVersionRun_4b05 {
  strings:
    $key_4b05 = { 18 6a [2] 3c 64 [2] 17 48 [2] 39 6a [2] 2d 71 [2] 22 6b [2] 3c 76 [2] 3e 77 [2] 25 71 [2] 39 76 [2] 25 59 }

  condition:
    any of them
}