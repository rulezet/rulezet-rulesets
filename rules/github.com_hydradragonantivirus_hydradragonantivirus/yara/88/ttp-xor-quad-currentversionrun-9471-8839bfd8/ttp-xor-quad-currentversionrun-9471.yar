rule TTP_XOR_QUAD_CurrentVersionRun_9471 {
  strings:
    $key_9471 = { c7 1e [2] e3 10 [2] c8 3c [2] e6 1e [2] f2 05 [2] fd 1f [2] e3 02 [2] e1 03 [2] fa 05 [2] e6 02 [2] fa 2d }

  condition:
    any of them
}