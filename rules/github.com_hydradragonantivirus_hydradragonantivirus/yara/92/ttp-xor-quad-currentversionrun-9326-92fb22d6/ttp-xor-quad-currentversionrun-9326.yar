rule TTP_XOR_QUAD_CurrentVersionRun_9326 {
  strings:
    $key_9326 = { c0 49 [2] e4 47 [2] cf 6b [2] e1 49 [2] f5 52 [2] fa 48 [2] e4 55 [2] e6 54 [2] fd 52 [2] e1 55 [2] fd 7a }

  condition:
    any of them
}