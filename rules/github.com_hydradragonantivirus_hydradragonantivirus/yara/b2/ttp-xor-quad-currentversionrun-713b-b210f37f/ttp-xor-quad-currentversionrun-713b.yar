rule TTP_XOR_QUAD_CurrentVersionRun_713b {
  strings:
    $key_713b = { 22 54 [2] 06 5a [2] 2d 76 [2] 03 54 [2] 17 4f [2] 18 55 [2] 06 48 [2] 04 49 [2] 1f 4f [2] 03 48 [2] 1f 67 }

  condition:
    any of them
}