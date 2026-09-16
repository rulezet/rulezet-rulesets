rule TTP_XOR_QUAD_CurrentVersionRun_31a2 {
  strings:
    $key_31a2 = { 62 cd [2] 46 c3 [2] 6d ef [2] 43 cd [2] 57 d6 [2] 58 cc [2] 46 d1 [2] 44 d0 [2] 5f d6 [2] 43 d1 [2] 5f fe }

  condition:
    any of them
}