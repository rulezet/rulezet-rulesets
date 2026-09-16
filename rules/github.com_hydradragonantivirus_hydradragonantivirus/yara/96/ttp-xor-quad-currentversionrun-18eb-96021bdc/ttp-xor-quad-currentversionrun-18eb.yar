rule TTP_XOR_QUAD_CurrentVersionRun_18eb {
  strings:
    $key_18eb = { 4b 84 [2] 6f 8a [2] 44 a6 [2] 6a 84 [2] 7e 9f [2] 71 85 [2] 6f 98 [2] 6d 99 [2] 76 9f [2] 6a 98 [2] 76 b7 }

  condition:
    any of them
}