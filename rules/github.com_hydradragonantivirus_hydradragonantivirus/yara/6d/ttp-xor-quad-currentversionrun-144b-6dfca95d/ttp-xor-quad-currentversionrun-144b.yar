rule TTP_XOR_QUAD_CurrentVersionRun_144b {
  strings:
    $key_144b = { 47 24 [2] 63 2a [2] 48 06 [2] 66 24 [2] 72 3f [2] 7d 25 [2] 63 38 [2] 61 39 [2] 7a 3f [2] 66 38 [2] 7a 17 }

  condition:
    any of them
}