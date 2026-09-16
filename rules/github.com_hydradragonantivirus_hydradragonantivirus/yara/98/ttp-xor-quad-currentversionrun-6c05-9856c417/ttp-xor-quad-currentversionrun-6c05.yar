rule TTP_XOR_QUAD_CurrentVersionRun_6c05 {
  strings:
    $key_6c05 = { 3f 6a [2] 1b 64 [2] 30 48 [2] 1e 6a [2] 0a 71 [2] 05 6b [2] 1b 76 [2] 19 77 [2] 02 71 [2] 1e 76 [2] 02 59 }

  condition:
    any of them
}