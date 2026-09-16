rule TTP_XOR_QUAD_CurrentVersionRun_93e0 {
  strings:
    $key_93e0 = { c0 8f [2] e4 81 [2] cf ad [2] e1 8f [2] f5 94 [2] fa 8e [2] e4 93 [2] e6 92 [2] fd 94 [2] e1 93 [2] fd bc }

  condition:
    any of them
}