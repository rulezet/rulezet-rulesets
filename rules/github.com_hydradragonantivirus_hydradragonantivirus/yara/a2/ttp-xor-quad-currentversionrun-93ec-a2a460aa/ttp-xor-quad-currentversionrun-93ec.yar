rule TTP_XOR_QUAD_CurrentVersionRun_93ec {
  strings:
    $key_93ec = { c0 83 [2] e4 8d [2] cf a1 [2] e1 83 [2] f5 98 [2] fa 82 [2] e4 9f [2] e6 9e [2] fd 98 [2] e1 9f [2] fd b0 }

  condition:
    any of them
}