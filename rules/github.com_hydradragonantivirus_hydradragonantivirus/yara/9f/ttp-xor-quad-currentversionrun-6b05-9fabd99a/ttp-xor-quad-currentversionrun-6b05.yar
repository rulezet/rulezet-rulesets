rule TTP_XOR_QUAD_CurrentVersionRun_6b05 {
  strings:
    $key_6b05 = { 38 6a [2] 1c 64 [2] 37 48 [2] 19 6a [2] 0d 71 [2] 02 6b [2] 1c 76 [2] 1e 77 [2] 05 71 [2] 19 76 [2] 05 59 }

  condition:
    any of them
}