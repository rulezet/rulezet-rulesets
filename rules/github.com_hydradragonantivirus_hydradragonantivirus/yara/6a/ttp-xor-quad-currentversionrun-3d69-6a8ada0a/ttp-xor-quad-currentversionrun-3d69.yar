rule TTP_XOR_QUAD_CurrentVersionRun_3d69 {
  strings:
    $key_3d69 = { 6e 06 [2] 4a 08 [2] 61 24 [2] 4f 06 [2] 5b 1d [2] 54 07 [2] 4a 1a [2] 48 1b [2] 53 1d [2] 4f 1a [2] 53 35 }

  condition:
    any of them
}