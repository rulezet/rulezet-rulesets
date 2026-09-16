rule TTP_XOR_QUAD_CurrentVersionRun_6171 {
  strings:
    $key_6171 = { 32 1e [2] 16 10 [2] 3d 3c [2] 13 1e [2] 07 05 [2] 08 1f [2] 16 02 [2] 14 03 [2] 0f 05 [2] 13 02 [2] 0f 2d }

  condition:
    any of them
}