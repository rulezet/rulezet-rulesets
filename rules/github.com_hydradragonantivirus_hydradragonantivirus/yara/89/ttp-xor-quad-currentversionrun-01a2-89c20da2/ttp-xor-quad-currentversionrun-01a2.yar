rule TTP_XOR_QUAD_CurrentVersionRun_01a2 {
  strings:
    $key_01a2 = { 52 cd [2] 76 c3 [2] 5d ef [2] 73 cd [2] 67 d6 [2] 68 cc [2] 76 d1 [2] 74 d0 [2] 6f d6 [2] 73 d1 [2] 6f fe }

  condition:
    any of them
}