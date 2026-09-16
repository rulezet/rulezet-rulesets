rule TTP_XOR_QUAD_CurrentVersionRun_9a30 {
  strings:
    $key_9a30 = { c9 5f [2] ed 51 [2] c6 7d [2] e8 5f [2] fc 44 [2] f3 5e [2] ed 43 [2] ef 42 [2] f4 44 [2] e8 43 [2] f4 6c }

  condition:
    any of them
}