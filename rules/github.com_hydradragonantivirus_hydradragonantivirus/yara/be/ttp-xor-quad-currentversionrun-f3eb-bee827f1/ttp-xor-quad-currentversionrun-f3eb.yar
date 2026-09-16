rule TTP_XOR_QUAD_CurrentVersionRun_f3eb {
  strings:
    $key_f3eb = { a0 84 [2] 84 8a [2] af a6 [2] 81 84 [2] 95 9f [2] 9a 85 [2] 84 98 [2] 86 99 [2] 9d 9f [2] 81 98 [2] 9d b7 }

  condition:
    any of them
}