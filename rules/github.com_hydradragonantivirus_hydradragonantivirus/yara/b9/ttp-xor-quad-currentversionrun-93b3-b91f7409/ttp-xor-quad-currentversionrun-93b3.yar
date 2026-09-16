rule TTP_XOR_QUAD_CurrentVersionRun_93b3 {
  strings:
    $key_93b3 = { c0 dc [2] e4 d2 [2] cf fe [2] e1 dc [2] f5 c7 [2] fa dd [2] e4 c0 [2] e6 c1 [2] fd c7 [2] e1 c0 [2] fd ef }

  condition:
    any of them
}