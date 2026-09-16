rule TTP_XOR_QUAD_CurrentVersionRun_58eb {
  strings:
    $key_58eb = { 0b 84 [2] 2f 8a [2] 04 a6 [2] 2a 84 [2] 3e 9f [2] 31 85 [2] 2f 98 [2] 2d 99 [2] 36 9f [2] 2a 98 [2] 36 b7 }

  condition:
    any of them
}