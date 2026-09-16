rule TTP_XOR_QUAD_CurrentVersionRun_ee91 {
  strings:
    $key_ee91 = { bd fe [2] 99 f0 [2] b2 dc [2] 9c fe [2] 88 e5 [2] 87 ff [2] 99 e2 [2] 9b e3 [2] 80 e5 [2] 9c e2 [2] 80 cd }

  condition:
    any of them
}