rule TTP_XOR_QUAD_CurrentVersionRun_156b {
  strings:
    $key_156b = { 46 04 [2] 62 0a [2] 49 26 [2] 67 04 [2] 73 1f [2] 7c 05 [2] 62 18 [2] 60 19 [2] 7b 1f [2] 67 18 [2] 7b 37 }

  condition:
    any of them
}