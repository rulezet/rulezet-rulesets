rule TTP_XOR_QUAD_CurrentVersionRun_79eb {
  strings:
    $key_79eb = { 2a 84 [2] 0e 8a [2] 25 a6 [2] 0b 84 [2] 1f 9f [2] 10 85 [2] 0e 98 [2] 0c 99 [2] 17 9f [2] 0b 98 [2] 17 b7 }

  condition:
    any of them
}