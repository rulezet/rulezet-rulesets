rule TTP_XOR_QUAD_CurrentVersionRun_3b6b {
  strings:
    $key_3b6b = { 68 04 [2] 4c 0a [2] 67 26 [2] 49 04 [2] 5d 1f [2] 52 05 [2] 4c 18 [2] 4e 19 [2] 55 1f [2] 49 18 [2] 55 37 }

  condition:
    any of them
}