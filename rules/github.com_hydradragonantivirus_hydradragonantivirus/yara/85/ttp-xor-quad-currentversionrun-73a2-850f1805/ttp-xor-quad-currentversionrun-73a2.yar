rule TTP_XOR_QUAD_CurrentVersionRun_73a2 {
  strings:
    $key_73a2 = { 20 cd [2] 04 c3 [2] 2f ef [2] 01 cd [2] 15 d6 [2] 1a cc [2] 04 d1 [2] 06 d0 [2] 1d d6 [2] 01 d1 [2] 1d fe }

  condition:
    any of them
}