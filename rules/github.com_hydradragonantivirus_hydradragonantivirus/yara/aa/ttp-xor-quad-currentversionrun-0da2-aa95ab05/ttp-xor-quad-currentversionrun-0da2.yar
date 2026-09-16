rule TTP_XOR_QUAD_CurrentVersionRun_0da2 {
  strings:
    $key_0da2 = { 5e cd [2] 7a c3 [2] 51 ef [2] 7f cd [2] 6b d6 [2] 64 cc [2] 7a d1 [2] 78 d0 [2] 63 d6 [2] 7f d1 [2] 63 fe }

  condition:
    any of them
}