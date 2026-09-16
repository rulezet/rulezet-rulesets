rule TTP_XOR_QUAD_CurrentVersionRun_f6eb {
  strings:
    $key_f6eb = { a5 84 [2] 81 8a [2] aa a6 [2] 84 84 [2] 90 9f [2] 9f 85 [2] 81 98 [2] 83 99 [2] 98 9f [2] 84 98 [2] 98 b7 }

  condition:
    any of them
}