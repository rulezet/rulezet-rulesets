rule TTP_XOR_QUAD_CurrentVersionRun_55a2 {
  strings:
    $key_55a2 = { 06 cd [2] 22 c3 [2] 09 ef [2] 27 cd [2] 33 d6 [2] 3c cc [2] 22 d1 [2] 20 d0 [2] 3b d6 [2] 27 d1 [2] 3b fe }

  condition:
    any of them
}