rule TTP_XOR_QUAD_CurrentVersionRun_487b {
  strings:
    $key_487b = { 1b 14 [2] 3f 1a [2] 14 36 [2] 3a 14 [2] 2e 0f [2] 21 15 [2] 3f 08 [2] 3d 09 [2] 26 0f [2] 3a 08 [2] 26 27 }

  condition:
    any of them
}