rule TTP_XOR_QUAD_CurrentVersionRun_3deb {
  strings:
    $key_3deb = { 6e 84 [2] 4a 8a [2] 61 a6 [2] 4f 84 [2] 5b 9f [2] 54 85 [2] 4a 98 [2] 48 99 [2] 53 9f [2] 4f 98 [2] 53 b7 }

  condition:
    any of them
}