rule TTP_XOR_QUAD_CurrentVersionRun_1949 {
  strings:
    $key_1949 = { 4a 26 [2] 6e 28 [2] 45 04 [2] 6b 26 [2] 7f 3d [2] 70 27 [2] 6e 3a [2] 6c 3b [2] 77 3d [2] 6b 3a [2] 77 15 }

  condition:
    any of them
}