rule TTP_XOR_QUAD_CurrentVersionRun_3949 {
  strings:
    $key_3949 = { 6a 26 [2] 4e 28 [2] 65 04 [2] 4b 26 [2] 5f 3d [2] 50 27 [2] 4e 3a [2] 4c 3b [2] 57 3d [2] 4b 3a [2] 57 15 }

  condition:
    any of them
}