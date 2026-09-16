rule TTP_XOR_QUAD_CurrentVersionRun_2da2 {
  strings:
    $key_2da2 = { 7e cd [2] 5a c3 [2] 71 ef [2] 5f cd [2] 4b d6 [2] 44 cc [2] 5a d1 [2] 58 d0 [2] 43 d6 [2] 5f d1 [2] 43 fe }

  condition:
    any of them
}