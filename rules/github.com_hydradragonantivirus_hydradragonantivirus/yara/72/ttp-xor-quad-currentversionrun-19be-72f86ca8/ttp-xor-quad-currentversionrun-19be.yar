rule TTP_XOR_QUAD_CurrentVersionRun_19be {
  strings:
    $key_19be = { 4a d1 [2] 6e df [2] 45 f3 [2] 6b d1 [2] 7f ca [2] 70 d0 [2] 6e cd [2] 6c cc [2] 77 ca [2] 6b cd [2] 77 e2 }

  condition:
    any of them
}