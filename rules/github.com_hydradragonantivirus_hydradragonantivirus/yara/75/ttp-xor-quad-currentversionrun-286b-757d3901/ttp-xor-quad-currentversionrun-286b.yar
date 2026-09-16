rule TTP_XOR_QUAD_CurrentVersionRun_286b {
  strings:
    $key_286b = { 7b 04 [2] 5f 0a [2] 74 26 [2] 5a 04 [2] 4e 1f [2] 41 05 [2] 5f 18 [2] 5d 19 [2] 46 1f [2] 5a 18 [2] 46 37 }

  condition:
    any of them
}