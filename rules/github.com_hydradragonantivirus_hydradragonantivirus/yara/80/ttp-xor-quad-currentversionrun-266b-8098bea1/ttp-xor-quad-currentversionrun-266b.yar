rule TTP_XOR_QUAD_CurrentVersionRun_266b {
  strings:
    $key_266b = { 75 04 [2] 51 0a [2] 7a 26 [2] 54 04 [2] 40 1f [2] 4f 05 [2] 51 18 [2] 53 19 [2] 48 1f [2] 54 18 [2] 48 37 }

  condition:
    any of them
}