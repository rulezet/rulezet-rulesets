rule TTP_XOR_QUAD_CurrentVersionRun_90ed {
  strings:
    $key_90ed = { c3 82 [2] e7 8c [2] cc a0 [2] e2 82 [2] f6 99 [2] f9 83 [2] e7 9e [2] e5 9f [2] fe 99 [2] e2 9e [2] fe b1 }

  condition:
    any of them
}