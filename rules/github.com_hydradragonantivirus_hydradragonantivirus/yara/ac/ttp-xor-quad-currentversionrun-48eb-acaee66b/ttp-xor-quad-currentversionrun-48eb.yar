rule TTP_XOR_QUAD_CurrentVersionRun_48eb {
  strings:
    $key_48eb = { 1b 84 [2] 3f 8a [2] 14 a6 [2] 3a 84 [2] 2e 9f [2] 21 85 [2] 3f 98 [2] 3d 99 [2] 26 9f [2] 3a 98 [2] 26 b7 }

  condition:
    any of them
}