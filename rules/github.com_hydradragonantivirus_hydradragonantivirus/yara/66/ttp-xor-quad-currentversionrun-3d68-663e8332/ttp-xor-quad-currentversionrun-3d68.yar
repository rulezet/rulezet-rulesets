rule TTP_XOR_QUAD_CurrentVersionRun_3d68 {
  strings:
    $key_3d68 = { 6e 07 [2] 4a 09 [2] 61 25 [2] 4f 07 [2] 5b 1c [2] 54 06 [2] 4a 1b [2] 48 1a [2] 53 1c [2] 4f 1b [2] 53 34 }

  condition:
    any of them
}