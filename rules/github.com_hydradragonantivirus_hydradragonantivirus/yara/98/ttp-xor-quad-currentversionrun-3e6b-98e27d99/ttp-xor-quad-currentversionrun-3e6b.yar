rule TTP_XOR_QUAD_CurrentVersionRun_3e6b {
  strings:
    $key_3e6b = { 6d 04 [2] 49 0a [2] 62 26 [2] 4c 04 [2] 58 1f [2] 57 05 [2] 49 18 [2] 4b 19 [2] 50 1f [2] 4c 18 [2] 50 37 }

  condition:
    any of them
}