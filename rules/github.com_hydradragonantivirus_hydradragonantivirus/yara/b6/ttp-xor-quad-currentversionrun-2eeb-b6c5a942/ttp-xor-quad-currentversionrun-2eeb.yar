rule TTP_XOR_QUAD_CurrentVersionRun_2eeb {
  strings:
    $key_2eeb = { 7d 84 [2] 59 8a [2] 72 a6 [2] 5c 84 [2] 48 9f [2] 47 85 [2] 59 98 [2] 5b 99 [2] 40 9f [2] 5c 98 [2] 40 b7 }

  condition:
    any of them
}