rule TTP_XOR_QUAD_CurrentVersionRun_3d44 {
  strings:
    $key_3d44 = { 6e 2b [2] 4a 25 [2] 61 09 [2] 4f 2b [2] 5b 30 [2] 54 2a [2] 4a 37 [2] 48 36 [2] 53 30 [2] 4f 37 [2] 53 18 }

  condition:
    any of them
}