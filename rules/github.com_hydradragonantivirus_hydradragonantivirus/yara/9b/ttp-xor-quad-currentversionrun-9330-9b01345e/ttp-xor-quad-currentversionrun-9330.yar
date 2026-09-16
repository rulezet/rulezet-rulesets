rule TTP_XOR_QUAD_CurrentVersionRun_9330 {
  strings:
    $key_9330 = { c0 5f [2] e4 51 [2] cf 7d [2] e1 5f [2] f5 44 [2] fa 5e [2] e4 43 [2] e6 42 [2] fd 44 [2] e1 43 [2] fd 6c }

  condition:
    any of them
}