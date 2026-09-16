rule TTP_XOR_QUAD_CurrentVersionRun_340b {
  strings:
    $key_340b = { 67 64 [2] 43 6a [2] 68 46 [2] 46 64 [2] 52 7f [2] 5d 65 [2] 43 78 [2] 41 79 [2] 5a 7f [2] 46 78 [2] 5a 57 }

  condition:
    any of them
}