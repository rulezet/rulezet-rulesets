rule TTP_XOR_QUAD_CurrentVersionRun_5f3b {
  strings:
    $key_5f3b = { 0c 54 [2] 28 5a [2] 03 76 [2] 2d 54 [2] 39 4f [2] 36 55 [2] 28 48 [2] 2a 49 [2] 31 4f [2] 2d 48 [2] 31 67 }

  condition:
    any of them
}