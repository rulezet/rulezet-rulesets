rule TTP_XOR_QUAD_CurrentVersionRun_3d55 {
  strings:
    $key_3d55 = { 6e 3a [2] 4a 34 [2] 61 18 [2] 4f 3a [2] 5b 21 [2] 54 3b [2] 4a 26 [2] 48 27 [2] 53 21 [2] 4f 26 [2] 53 09 }

  condition:
    any of them
}