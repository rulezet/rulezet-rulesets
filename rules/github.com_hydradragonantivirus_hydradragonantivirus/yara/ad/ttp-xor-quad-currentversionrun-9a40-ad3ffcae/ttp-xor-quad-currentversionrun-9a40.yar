rule TTP_XOR_QUAD_CurrentVersionRun_9a40 {
  strings:
    $key_9a40 = { c9 2f [2] ed 21 [2] c6 0d [2] e8 2f [2] fc 34 [2] f3 2e [2] ed 33 [2] ef 32 [2] f4 34 [2] e8 33 [2] f4 1c }

  condition:
    any of them
}