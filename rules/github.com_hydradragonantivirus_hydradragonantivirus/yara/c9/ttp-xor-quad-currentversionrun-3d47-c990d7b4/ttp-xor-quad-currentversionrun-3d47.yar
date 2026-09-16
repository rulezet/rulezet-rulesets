rule TTP_XOR_QUAD_CurrentVersionRun_3d47 {
  strings:
    $key_3d47 = { 6e 28 [2] 4a 26 [2] 61 0a [2] 4f 28 [2] 5b 33 [2] 54 29 [2] 4a 34 [2] 48 35 [2] 53 33 [2] 4f 34 [2] 53 1b }

  condition:
    any of them
}