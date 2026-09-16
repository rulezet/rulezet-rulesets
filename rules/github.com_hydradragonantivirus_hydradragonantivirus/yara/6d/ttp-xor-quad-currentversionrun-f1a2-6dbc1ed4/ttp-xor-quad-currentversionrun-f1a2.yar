rule TTP_XOR_QUAD_CurrentVersionRun_f1a2 {
  strings:
    $key_f1a2 = { a2 cd [2] 86 c3 [2] ad ef [2] 83 cd [2] 97 d6 [2] 98 cc [2] 86 d1 [2] 84 d0 [2] 9f d6 [2] 83 d1 [2] 9f fe }

  condition:
    any of them
}