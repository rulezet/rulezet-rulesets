rule TTP_XOR_QUAD_CurrentVersionRun_04eb {
  strings:
    $key_04eb = { 57 84 [2] 73 8a [2] 58 a6 [2] 76 84 [2] 62 9f [2] 6d 85 [2] 73 98 [2] 71 99 [2] 6a 9f [2] 76 98 [2] 6a b7 }

  condition:
    any of them
}