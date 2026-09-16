rule TTP_XOR_QUAD_CurrentVersionRun_e7eb {
  strings:
    $key_e7eb = { b4 84 [2] 90 8a [2] bb a6 [2] 95 84 [2] 81 9f [2] 8e 85 [2] 90 98 [2] 92 99 [2] 89 9f [2] 95 98 [2] 89 b7 }

  condition:
    any of them
}