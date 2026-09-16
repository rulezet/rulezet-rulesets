rule TTP_XOR_QUAD_CurrentVersionRun_6eeb {
  strings:
    $key_6eeb = { 3d 84 [2] 19 8a [2] 32 a6 [2] 1c 84 [2] 08 9f [2] 07 85 [2] 19 98 [2] 1b 99 [2] 00 9f [2] 1c 98 [2] 00 b7 }

  condition:
    any of them
}