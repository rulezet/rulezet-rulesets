rule TTP_XOR_QUAD_CurrentVersionRun_49eb {
  strings:
    $key_49eb = { 1a 84 [2] 3e 8a [2] 15 a6 [2] 3b 84 [2] 2f 9f [2] 20 85 [2] 3e 98 [2] 3c 99 [2] 27 9f [2] 3b 98 [2] 27 b7 }

  condition:
    any of them
}