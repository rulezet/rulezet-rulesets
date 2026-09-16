rule TTP_XOR_QUAD_CurrentVersionRun_51a2 {
  strings:
    $key_51a2 = { 02 cd [2] 26 c3 [2] 0d ef [2] 23 cd [2] 37 d6 [2] 38 cc [2] 26 d1 [2] 24 d0 [2] 3f d6 [2] 23 d1 [2] 3f fe }

  condition:
    any of them
}