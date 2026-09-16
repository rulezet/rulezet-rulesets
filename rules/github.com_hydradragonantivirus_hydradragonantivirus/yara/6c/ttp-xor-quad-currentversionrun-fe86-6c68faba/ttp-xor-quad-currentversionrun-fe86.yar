rule TTP_XOR_QUAD_CurrentVersionRun_fe86 {
  strings:
    $key_fe86 = { ad e9 [2] 89 e7 [2] a2 cb [2] 8c e9 [2] 98 f2 [2] 97 e8 [2] 89 f5 [2] 8b f4 [2] 90 f2 [2] 8c f5 [2] 90 da }

  condition:
    any of them
}