rule TTP_XOR_QUAD_CurrentVersionRun_160b {
  strings:
    $key_160b = { 45 64 [2] 61 6a [2] 4a 46 [2] 64 64 [2] 70 7f [2] 7f 65 [2] 61 78 [2] 63 79 [2] 78 7f [2] 64 78 [2] 78 57 }

  condition:
    any of them
}