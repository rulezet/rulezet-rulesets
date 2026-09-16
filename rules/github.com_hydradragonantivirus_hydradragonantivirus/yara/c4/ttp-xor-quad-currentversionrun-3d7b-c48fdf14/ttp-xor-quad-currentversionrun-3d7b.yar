rule TTP_XOR_QUAD_CurrentVersionRun_3d7b {
  strings:
    $key_3d7b = { 6e 14 [2] 4a 1a [2] 61 36 [2] 4f 14 [2] 5b 0f [2] 54 15 [2] 4a 08 [2] 48 09 [2] 53 0f [2] 4f 08 [2] 53 27 }

  condition:
    any of them
}