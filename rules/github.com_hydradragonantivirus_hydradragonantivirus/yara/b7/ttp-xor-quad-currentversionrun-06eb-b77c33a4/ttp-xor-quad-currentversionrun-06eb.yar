rule TTP_XOR_QUAD_CurrentVersionRun_06eb {
  strings:
    $key_06eb = { 55 84 [2] 71 8a [2] 5a a6 [2] 74 84 [2] 60 9f [2] 6f 85 [2] 71 98 [2] 73 99 [2] 68 9f [2] 74 98 [2] 68 b7 }

  condition:
    any of them
}