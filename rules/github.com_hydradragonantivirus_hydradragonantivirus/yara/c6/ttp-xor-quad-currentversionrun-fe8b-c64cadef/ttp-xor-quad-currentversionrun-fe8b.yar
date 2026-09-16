rule TTP_XOR_QUAD_CurrentVersionRun_fe8b {
  strings:
    $key_fe8b = { ad e4 [2] 89 ea [2] a2 c6 [2] 8c e4 [2] 98 ff [2] 97 e5 [2] 89 f8 [2] 8b f9 [2] 90 ff [2] 8c f8 [2] 90 d7 }

  condition:
    any of them
}