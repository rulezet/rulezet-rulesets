rule TTP_XOR_QUAD_CurrentVersionRun_3327 {
  strings:
    $key_3327 = { 60 48 [2] 44 46 [2] 6f 6a [2] 41 48 [2] 55 53 [2] 5a 49 [2] 44 54 [2] 46 55 [2] 5d 53 [2] 41 54 [2] 5d 7b }

  condition:
    any of them
}