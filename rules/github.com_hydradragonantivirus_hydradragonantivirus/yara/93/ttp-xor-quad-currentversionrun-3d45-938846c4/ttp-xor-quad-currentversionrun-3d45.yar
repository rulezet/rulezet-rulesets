rule TTP_XOR_QUAD_CurrentVersionRun_3d45 {
  strings:
    $key_3d45 = { 6e 2a [2] 4a 24 [2] 61 08 [2] 4f 2a [2] 5b 31 [2] 54 2b [2] 4a 36 [2] 48 37 [2] 53 31 [2] 4f 36 [2] 53 19 }

  condition:
    any of them
}