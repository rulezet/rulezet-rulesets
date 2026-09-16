rule TTP_XOR_QUAD_CurrentVersionRun_3d49 {
  strings:
    $key_3d49 = { 6e 26 [2] 4a 28 [2] 61 04 [2] 4f 26 [2] 5b 3d [2] 54 27 [2] 4a 3a [2] 48 3b [2] 53 3d [2] 4f 3a [2] 53 15 }

  condition:
    any of them
}