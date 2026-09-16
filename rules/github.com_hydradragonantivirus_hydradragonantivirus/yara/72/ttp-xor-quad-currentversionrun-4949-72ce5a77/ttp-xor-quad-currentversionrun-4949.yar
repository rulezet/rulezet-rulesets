rule TTP_XOR_QUAD_CurrentVersionRun_4949 {
  strings:
    $key_4949 = { 1a 26 [2] 3e 28 [2] 15 04 [2] 3b 26 [2] 2f 3d [2] 20 27 [2] 3e 3a [2] 3c 3b [2] 27 3d [2] 3b 3a [2] 27 15 }

  condition:
    any of them
}