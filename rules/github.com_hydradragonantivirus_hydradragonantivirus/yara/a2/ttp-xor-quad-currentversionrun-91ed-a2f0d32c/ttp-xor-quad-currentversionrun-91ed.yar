rule TTP_XOR_QUAD_CurrentVersionRun_91ed {
  strings:
    $key_91ed = { c2 82 [2] e6 8c [2] cd a0 [2] e3 82 [2] f7 99 [2] f8 83 [2] e6 9e [2] e4 9f [2] ff 99 [2] e3 9e [2] ff b1 }

  condition:
    any of them
}