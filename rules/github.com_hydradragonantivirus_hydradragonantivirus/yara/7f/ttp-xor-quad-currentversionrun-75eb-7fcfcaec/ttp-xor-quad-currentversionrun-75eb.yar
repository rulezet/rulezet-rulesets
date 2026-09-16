rule TTP_XOR_QUAD_CurrentVersionRun_75eb {
  strings:
    $key_75eb = { 26 84 [2] 02 8a [2] 29 a6 [2] 07 84 [2] 13 9f [2] 1c 85 [2] 02 98 [2] 00 99 [2] 1b 9f [2] 07 98 [2] 1b b7 }

  condition:
    any of them
}