rule TTP_XOR_QUAD_CurrentVersionRun_03a2 {
  strings:
    $key_03a2 = { 50 cd [2] 74 c3 [2] 5f ef [2] 71 cd [2] 65 d6 [2] 6a cc [2] 74 d1 [2] 76 d0 [2] 6d d6 [2] 71 d1 [2] 6d fe }

  condition:
    any of them
}