rule TTP_XOR_QUAD_CurrentVersionRun_0deb {
  strings:
    $key_0deb = { 5e 84 [2] 7a 8a [2] 51 a6 [2] 7f 84 [2] 6b 9f [2] 64 85 [2] 7a 98 [2] 78 99 [2] 63 9f [2] 7f 98 [2] 63 b7 }

  condition:
    any of them
}