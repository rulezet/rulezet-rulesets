rule TTP_XOR_QUAD_CurrentVersionRun_3d27 {
  strings:
    $key_3d27 = { 6e 48 [2] 4a 46 [2] 61 6a [2] 4f 48 [2] 5b 53 [2] 54 49 [2] 4a 54 [2] 48 55 [2] 53 53 [2] 4f 54 [2] 53 7b }

  condition:
    any of them
}