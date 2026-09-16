rule TTP_XOR_QUAD_CurrentVersionRun_161b {
  strings:
    $key_161b = { 45 74 [2] 61 7a [2] 4a 56 [2] 64 74 [2] 70 6f [2] 7f 75 [2] 61 68 [2] 63 69 [2] 78 6f [2] 64 68 [2] 78 47 }

  condition:
    any of them
}