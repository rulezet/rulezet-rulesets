rule TTP_XOR_QUAD_CurrentVersionRun_180b {
  strings:
    $key_180b = { 4b 64 [2] 6f 6a [2] 44 46 [2] 6a 64 [2] 7e 7f [2] 71 65 [2] 6f 78 [2] 6d 79 [2] 76 7f [2] 6a 78 [2] 76 57 }

  condition:
    any of them
}