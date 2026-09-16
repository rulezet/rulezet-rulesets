rule TTP_XOR_QUAD_CurrentVersionRun_9af6 {
  strings:
    $key_9af6 = { c9 99 [2] ed 97 [2] c6 bb [2] e8 99 [2] fc 82 [2] f3 98 [2] ed 85 [2] ef 84 [2] f4 82 [2] e8 85 [2] f4 aa }

  condition:
    any of them
}