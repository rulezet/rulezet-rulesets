rule TTP_XOR_QUAD_CurrentVersionRun_91f1 {
  strings:
    $key_91f1 = { c2 9e [2] e6 90 [2] cd bc [2] e3 9e [2] f7 85 [2] f8 9f [2] e6 82 [2] e4 83 [2] ff 85 [2] e3 82 [2] ff ad }

  condition:
    any of them
}