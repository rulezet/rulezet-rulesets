rule TTP_XOR_QUAD_CurrentVersionRun_41a2 {
  strings:
    $key_41a2 = { 12 cd [2] 36 c3 [2] 1d ef [2] 33 cd [2] 27 d6 [2] 28 cc [2] 36 d1 [2] 34 d0 [2] 2f d6 [2] 33 d1 [2] 2f fe }

  condition:
    any of them
}