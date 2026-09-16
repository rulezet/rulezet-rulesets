rule TTP_XOR_QUAD_CurrentVersionRun_276b {
  strings:
    $key_276b = { 74 04 [2] 50 0a [2] 7b 26 [2] 55 04 [2] 41 1f [2] 4e 05 [2] 50 18 [2] 52 19 [2] 49 1f [2] 55 18 [2] 49 37 }

  condition:
    any of them
}