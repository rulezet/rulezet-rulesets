rule TTP_XOR_QUAD_CurrentVersionRun_13a2 {
  strings:
    $key_13a2 = { 40 cd [2] 64 c3 [2] 4f ef [2] 61 cd [2] 75 d6 [2] 7a cc [2] 64 d1 [2] 66 d0 [2] 7d d6 [2] 61 d1 [2] 7d fe }

  condition:
    any of them
}