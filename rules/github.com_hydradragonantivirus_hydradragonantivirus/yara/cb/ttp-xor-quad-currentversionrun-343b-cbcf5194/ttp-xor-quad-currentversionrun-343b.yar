rule TTP_XOR_QUAD_CurrentVersionRun_343b {
  strings:
    $key_343b = { 67 54 [2] 43 5a [2] 68 76 [2] 46 54 [2] 52 4f [2] 5d 55 [2] 43 48 [2] 41 49 [2] 5a 4f [2] 46 48 [2] 5a 67 }

  condition:
    any of them
}