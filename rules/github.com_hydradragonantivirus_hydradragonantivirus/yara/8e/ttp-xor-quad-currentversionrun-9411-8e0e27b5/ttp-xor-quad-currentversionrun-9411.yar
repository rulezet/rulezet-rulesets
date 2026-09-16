rule TTP_XOR_QUAD_CurrentVersionRun_9411 {
  strings:
    $key_9411 = { c7 7e [2] e3 70 [2] c8 5c [2] e6 7e [2] f2 65 [2] fd 7f [2] e3 62 [2] e1 63 [2] fa 65 [2] e6 62 [2] fa 4d }

  condition:
    any of them
}