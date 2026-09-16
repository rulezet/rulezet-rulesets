rule TTP_XOR_QUAD_CurrentVersionRun_eb91 {
  strings:
    $key_eb91 = { b8 fe [2] 9c f0 [2] b7 dc [2] 99 fe [2] 8d e5 [2] 82 ff [2] 9c e2 [2] 9e e3 [2] 85 e5 [2] 99 e2 [2] 85 cd }

  condition:
    any of them
}