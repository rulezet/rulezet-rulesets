rule TTP_XOR_QUAD_CurrentVersionRun_0849 {
  strings:
    $key_0849 = { 5b 26 [2] 7f 28 [2] 54 04 [2] 7a 26 [2] 6e 3d [2] 61 27 [2] 7f 3a [2] 7d 3b [2] 66 3d [2] 7a 3a [2] 66 15 }

  condition:
    any of them
}