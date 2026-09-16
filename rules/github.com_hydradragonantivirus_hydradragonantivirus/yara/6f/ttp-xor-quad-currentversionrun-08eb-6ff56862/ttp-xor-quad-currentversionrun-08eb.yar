rule TTP_XOR_QUAD_CurrentVersionRun_08eb {
  strings:
    $key_08eb = { 5b 84 [2] 7f 8a [2] 54 a6 [2] 7a 84 [2] 6e 9f [2] 61 85 [2] 7f 98 [2] 7d 99 [2] 66 9f [2] 7a 98 [2] 66 b7 }

  condition:
    any of them
}