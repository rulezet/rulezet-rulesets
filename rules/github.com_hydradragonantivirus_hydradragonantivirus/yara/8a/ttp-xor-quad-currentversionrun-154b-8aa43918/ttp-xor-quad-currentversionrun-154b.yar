rule TTP_XOR_QUAD_CurrentVersionRun_154b {
  strings:
    $key_154b = { 46 24 [2] 62 2a [2] 49 06 [2] 67 24 [2] 73 3f [2] 7c 25 [2] 62 38 [2] 60 39 [2] 7b 3f [2] 67 38 [2] 7b 17 }

  condition:
    any of them
}