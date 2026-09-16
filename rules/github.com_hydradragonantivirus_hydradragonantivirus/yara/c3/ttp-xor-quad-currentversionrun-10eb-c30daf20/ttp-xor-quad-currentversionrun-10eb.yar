rule TTP_XOR_QUAD_CurrentVersionRun_10eb {
  strings:
    $key_10eb = { 43 84 [2] 67 8a [2] 4c a6 [2] 62 84 [2] 76 9f [2] 79 85 [2] 67 98 [2] 65 99 [2] 7e 9f [2] 62 98 [2] 7e b7 }

  condition:
    any of them
}