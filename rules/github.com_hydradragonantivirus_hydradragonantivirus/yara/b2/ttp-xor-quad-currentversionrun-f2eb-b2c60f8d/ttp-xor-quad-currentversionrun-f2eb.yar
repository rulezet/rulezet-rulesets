rule TTP_XOR_QUAD_CurrentVersionRun_f2eb {
  strings:
    $key_f2eb = { a1 84 [2] 85 8a [2] ae a6 [2] 80 84 [2] 94 9f [2] 9b 85 [2] 85 98 [2] 87 99 [2] 9c 9f [2] 80 98 [2] 9c b7 }

  condition:
    any of them
}