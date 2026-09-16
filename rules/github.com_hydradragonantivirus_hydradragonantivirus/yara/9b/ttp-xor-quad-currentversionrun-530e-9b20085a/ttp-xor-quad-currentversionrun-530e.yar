rule TTP_XOR_QUAD_CurrentVersionRun_530e {
  strings:
    $key_530e = { 00 61 [2] 24 6f [2] 0f 43 [2] 21 61 [2] 35 7a [2] 3a 60 [2] 24 7d [2] 26 7c [2] 3d 7a [2] 21 7d [2] 3d 52 }

  condition:
    any of them
}