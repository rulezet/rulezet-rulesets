rule TTP_XOR_QUAD_CurrentVersionRun_fda2 {
  strings:
    $key_fda2 = { ae cd [2] 8a c3 [2] a1 ef [2] 8f cd [2] 9b d6 [2] 94 cc [2] 8a d1 [2] 88 d0 [2] 93 d6 [2] 8f d1 [2] 93 fe }

  condition:
    any of them
}