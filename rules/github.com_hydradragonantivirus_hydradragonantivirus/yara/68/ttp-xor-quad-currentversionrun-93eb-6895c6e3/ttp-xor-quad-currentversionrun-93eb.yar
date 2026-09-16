rule TTP_XOR_QUAD_CurrentVersionRun_93eb {
  strings:
    $key_93eb = { c0 84 [2] e4 8a [2] cf a6 [2] e1 84 [2] f5 9f [2] fa 85 [2] e4 98 [2] e6 99 [2] fd 9f [2] e1 98 [2] fd b7 }

  condition:
    any of them
}