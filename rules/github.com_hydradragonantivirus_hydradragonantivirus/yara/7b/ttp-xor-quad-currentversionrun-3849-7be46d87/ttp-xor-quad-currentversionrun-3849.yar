rule TTP_XOR_QUAD_CurrentVersionRun_3849 {
  strings:
    $key_3849 = { 6b 26 [2] 4f 28 [2] 64 04 [2] 4a 26 [2] 5e 3d [2] 51 27 [2] 4f 3a [2] 4d 3b [2] 56 3d [2] 4a 3a [2] 56 15 }

  condition:
    any of them
}