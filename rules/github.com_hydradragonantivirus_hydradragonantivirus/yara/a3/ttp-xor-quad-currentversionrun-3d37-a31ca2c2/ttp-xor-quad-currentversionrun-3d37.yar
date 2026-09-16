rule TTP_XOR_QUAD_CurrentVersionRun_3d37 {
  strings:
    $key_3d37 = { 6e 58 [2] 4a 56 [2] 61 7a [2] 4f 58 [2] 5b 43 [2] 54 59 [2] 4a 44 [2] 48 45 [2] 53 43 [2] 4f 44 [2] 53 6b }

  condition:
    any of them
}