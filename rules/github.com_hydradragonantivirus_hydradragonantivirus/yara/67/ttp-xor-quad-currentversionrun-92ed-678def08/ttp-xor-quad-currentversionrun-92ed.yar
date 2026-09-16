rule TTP_XOR_QUAD_CurrentVersionRun_92ed {
  strings:
    $key_92ed = { c1 82 [2] e5 8c [2] ce a0 [2] e0 82 [2] f4 99 [2] fb 83 [2] e5 9e [2] e7 9f [2] fc 99 [2] e0 9e [2] fc b1 }

  condition:
    any of them
}