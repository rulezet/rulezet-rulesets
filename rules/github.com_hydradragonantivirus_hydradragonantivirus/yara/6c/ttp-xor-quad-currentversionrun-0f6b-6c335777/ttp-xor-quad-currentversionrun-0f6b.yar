rule TTP_XOR_QUAD_CurrentVersionRun_0f6b {
  strings:
    $key_0f6b = { 5c 04 [2] 78 0a [2] 53 26 [2] 7d 04 [2] 69 1f [2] 66 05 [2] 78 18 [2] 7a 19 [2] 61 1f [2] 7d 18 [2] 61 37 }

  condition:
    any of them
}