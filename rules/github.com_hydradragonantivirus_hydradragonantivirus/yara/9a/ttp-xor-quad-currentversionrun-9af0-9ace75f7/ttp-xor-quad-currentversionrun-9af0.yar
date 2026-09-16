rule TTP_XOR_QUAD_CurrentVersionRun_9af0 {
  strings:
    $key_9af0 = { c9 9f [2] ed 91 [2] c6 bd [2] e8 9f [2] fc 84 [2] f3 9e [2] ed 83 [2] ef 82 [2] f4 84 [2] e8 83 [2] f4 ac }

  condition:
    any of them
}