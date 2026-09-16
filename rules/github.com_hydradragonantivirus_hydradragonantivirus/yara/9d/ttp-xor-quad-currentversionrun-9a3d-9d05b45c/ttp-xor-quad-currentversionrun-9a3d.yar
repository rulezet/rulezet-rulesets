rule TTP_XOR_QUAD_CurrentVersionRun_9a3d {
  strings:
    $key_9a3d = { c9 52 [2] ed 5c [2] c6 70 [2] e8 52 [2] fc 49 [2] f3 53 [2] ed 4e [2] ef 4f [2] f4 49 [2] e8 4e [2] f4 61 }

  condition:
    any of them
}