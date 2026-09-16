rule TTP_XOR_QUAD_CurrentVersionRun_9311 {
  strings:
    $key_9311 = { c0 7e [2] e4 70 [2] cf 5c [2] e1 7e [2] f5 65 [2] fa 7f [2] e4 62 [2] e6 63 [2] fd 65 [2] e1 62 [2] fd 4d }

  condition:
    any of them
}