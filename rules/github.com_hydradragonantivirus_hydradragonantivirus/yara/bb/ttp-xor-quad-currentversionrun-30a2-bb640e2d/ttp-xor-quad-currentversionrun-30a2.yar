rule TTP_XOR_QUAD_CurrentVersionRun_30a2 {
  strings:
    $key_30a2 = { 63 cd [2] 47 c3 [2] 6c ef [2] 42 cd [2] 56 d6 [2] 59 cc [2] 47 d1 [2] 45 d0 [2] 5e d6 [2] 42 d1 [2] 5e fe }

  condition:
    any of them
}