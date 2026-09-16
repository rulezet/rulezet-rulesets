rule TTP_XOR_QUAD_CurrentVersionRun_9a32 {
  strings:
    $key_9a32 = { c9 5d [2] ed 53 [2] c6 7f [2] e8 5d [2] fc 46 [2] f3 5c [2] ed 41 [2] ef 40 [2] f4 46 [2] e8 41 [2] f4 6e }

  condition:
    any of them
}