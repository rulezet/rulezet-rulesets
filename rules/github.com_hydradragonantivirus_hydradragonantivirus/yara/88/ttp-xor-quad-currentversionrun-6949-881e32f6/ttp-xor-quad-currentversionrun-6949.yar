rule TTP_XOR_QUAD_CurrentVersionRun_6949 {
  strings:
    $key_6949 = { 3a 26 [2] 1e 28 [2] 35 04 [2] 1b 26 [2] 0f 3d [2] 00 27 [2] 1e 3a [2] 1c 3b [2] 07 3d [2] 1b 3a [2] 07 15 }

  condition:
    any of them
}