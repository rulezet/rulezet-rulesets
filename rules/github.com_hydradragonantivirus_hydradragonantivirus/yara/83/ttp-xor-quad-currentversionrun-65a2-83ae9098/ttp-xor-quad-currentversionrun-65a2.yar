rule TTP_XOR_QUAD_CurrentVersionRun_65a2 {
  strings:
    $key_65a2 = { 36 cd [2] 12 c3 [2] 39 ef [2] 17 cd [2] 03 d6 [2] 0c cc [2] 12 d1 [2] 10 d0 [2] 0b d6 [2] 17 d1 [2] 0b fe }

  condition:
    any of them
}