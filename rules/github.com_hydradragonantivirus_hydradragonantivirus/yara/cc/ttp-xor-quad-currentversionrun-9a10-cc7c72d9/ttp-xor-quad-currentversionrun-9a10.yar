rule TTP_XOR_QUAD_CurrentVersionRun_9a10 {
  strings:
    $key_9a10 = { c9 7f [2] ed 71 [2] c6 5d [2] e8 7f [2] fc 64 [2] f3 7e [2] ed 63 [2] ef 62 [2] f4 64 [2] e8 63 [2] f4 4c }

  condition:
    any of them
}