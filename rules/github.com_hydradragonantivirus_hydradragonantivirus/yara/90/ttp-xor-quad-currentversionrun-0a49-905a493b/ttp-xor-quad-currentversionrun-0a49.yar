rule TTP_XOR_QUAD_CurrentVersionRun_0a49 {
  strings:
    $key_0a49 = { 59 26 [2] 7d 28 [2] 56 04 [2] 78 26 [2] 6c 3d [2] 63 27 [2] 7d 3a [2] 7f 3b [2] 64 3d [2] 78 3a [2] 64 15 }

  condition:
    any of them
}