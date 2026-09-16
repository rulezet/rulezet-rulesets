rule TTP_XOR_QUAD_CurrentVersionRun_9a1f {
  strings:
    $key_9a1f = { c9 70 [2] ed 7e [2] c6 52 [2] e8 70 [2] fc 6b [2] f3 71 [2] ed 6c [2] ef 6d [2] f4 6b [2] e8 6c [2] f4 43 }

  condition:
    any of them
}