rule TTP_XOR_QUAD_CurrentVersionRun_9aa2 {
  strings:
    $key_9aa2 = { c9 cd [2] ed c3 [2] c6 ef [2] e8 cd [2] fc d6 [2] f3 cc [2] ed d1 [2] ef d0 [2] f4 d6 [2] e8 d1 [2] f4 fe }

  condition:
    any of them
}