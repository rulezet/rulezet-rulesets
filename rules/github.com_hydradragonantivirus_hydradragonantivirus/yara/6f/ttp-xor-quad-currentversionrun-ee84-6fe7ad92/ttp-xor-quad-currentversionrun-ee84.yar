rule TTP_XOR_QUAD_CurrentVersionRun_ee84 {
  strings:
    $key_ee84 = { bd eb [2] 99 e5 [2] b2 c9 [2] 9c eb [2] 88 f0 [2] 87 ea [2] 99 f7 [2] 9b f6 [2] 80 f0 [2] 9c f7 [2] 80 d8 }

  condition:
    any of them
}