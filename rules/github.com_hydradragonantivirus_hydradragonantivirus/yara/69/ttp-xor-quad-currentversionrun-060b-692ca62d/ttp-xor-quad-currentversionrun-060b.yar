rule TTP_XOR_QUAD_CurrentVersionRun_060b {
  strings:
    $key_060b = { 55 64 [2] 71 6a [2] 5a 46 [2] 74 64 [2] 60 7f [2] 6f 65 [2] 71 78 [2] 73 79 [2] 68 7f [2] 74 78 [2] 68 57 }

  condition:
    any of them
}