rule TTP_XOR_QUAD_CurrentVersionRun_6da2 {
  strings:
    $key_6da2 = { 3e cd [2] 1a c3 [2] 31 ef [2] 1f cd [2] 0b d6 [2] 04 cc [2] 1a d1 [2] 18 d0 [2] 03 d6 [2] 1f d1 [2] 03 fe }

  condition:
    any of them
}