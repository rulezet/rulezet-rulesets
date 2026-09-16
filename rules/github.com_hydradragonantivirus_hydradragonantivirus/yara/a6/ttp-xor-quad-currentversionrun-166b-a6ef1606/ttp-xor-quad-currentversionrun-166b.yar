rule TTP_XOR_QUAD_CurrentVersionRun_166b {
  strings:
    $key_166b = { 45 04 [2] 61 0a [2] 4a 26 [2] 64 04 [2] 70 1f [2] 7f 05 [2] 61 18 [2] 63 19 [2] 78 1f [2] 64 18 [2] 78 37 }

  condition:
    any of them
}