rule TTP_XOR_QUAD_CurrentVersionRun_e7a3 {
  strings:
    $key_e7a3 = { b4 cc [2] 90 c2 [2] bb ee [2] 95 cc [2] 81 d7 [2] 8e cd [2] 90 d0 [2] 92 d1 [2] 89 d7 [2] 95 d0 [2] 89 ff }

  condition:
    any of them
}