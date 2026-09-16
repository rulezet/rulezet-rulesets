rule TTP_XOR_QUAD_CurrentVersionRun_9322 {
  strings:
    $key_9322 = { c0 4d [2] e4 43 [2] cf 6f [2] e1 4d [2] f5 56 [2] fa 4c [2] e4 51 [2] e6 50 [2] fd 56 [2] e1 51 [2] fd 7e }

  condition:
    any of them
}