rule TTP_XOR_QUAD_CurrentVersionRun_75a2 {
  strings:
    $key_75a2 = { 26 cd [2] 02 c3 [2] 29 ef [2] 07 cd [2] 13 d6 [2] 1c cc [2] 02 d1 [2] 00 d0 [2] 1b d6 [2] 07 d1 [2] 1b fe }

  condition:
    any of them
}