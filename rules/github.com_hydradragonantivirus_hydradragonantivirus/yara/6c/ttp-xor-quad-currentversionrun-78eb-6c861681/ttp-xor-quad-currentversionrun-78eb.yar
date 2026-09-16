rule TTP_XOR_QUAD_CurrentVersionRun_78eb {
  strings:
    $key_78eb = { 2b 84 [2] 0f 8a [2] 24 a6 [2] 0a 84 [2] 1e 9f [2] 11 85 [2] 0f 98 [2] 0d 99 [2] 16 9f [2] 0a 98 [2] 16 b7 }

  condition:
    any of them
}