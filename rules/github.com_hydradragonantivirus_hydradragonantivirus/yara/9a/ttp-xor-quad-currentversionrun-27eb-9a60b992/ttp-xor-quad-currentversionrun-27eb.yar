rule TTP_XOR_QUAD_CurrentVersionRun_27eb {
  strings:
    $key_27eb = { 74 84 [2] 50 8a [2] 7b a6 [2] 55 84 [2] 41 9f [2] 4e 85 [2] 50 98 [2] 52 99 [2] 49 9f [2] 55 98 [2] 49 b7 }

  condition:
    any of them
}