rule TTP_XOR_QUAD_CurrentVersionRun_05a2 {
  strings:
    $key_05a2 = { 56 cd [2] 72 c3 [2] 59 ef [2] 77 cd [2] 63 d6 [2] 6c cc [2] 72 d1 [2] 70 d0 [2] 6b d6 [2] 77 d1 [2] 6b fe }

  condition:
    any of them
}