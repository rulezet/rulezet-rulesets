rule TTP_XOR_QUAD_CurrentVersionRun_3d54 {
  strings:
    $key_3d54 = { 6e 3b [2] 4a 35 [2] 61 19 [2] 4f 3b [2] 5b 20 [2] 54 3a [2] 4a 27 [2] 48 26 [2] 53 20 [2] 4f 27 [2] 53 08 }

  condition:
    any of them
}